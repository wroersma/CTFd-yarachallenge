from CTFd.plugins.keys import get_key_class, KEY_CLASSES
from CTFd.plugins import challenges, register_plugin_assets_directory
from CTFd.plugins.keys import BaseKey
from flask import request, redirect, jsonify, url_for, session, abort
from CTFd.models import db, Challenges, WrongKeys, Keys, Teams, Awards, Solves
from CTFd import utils
import logging
import time
from CTFd.plugins.challenges import get_chal_class
import yara
import os


class YaraChallenge(challenges.BaseChallenge):
    """yarachallenge allows right and wrong answers and leaves the question open"""
    id = "yarachallenge"
    name = "yarachallenge"

    templates = {  # Handlebars templates used for each aspect of challenge editing & viewing
        'create': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-create.hbs',
        'update': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-update.hbs',
        'modal': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-modal.hbs',
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        'create': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-create.js',
        'update': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-update.js',
        'modal': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-modal.js',
    }

    def attempt(chal, request):
        """Attempt the user answer to see if it's right"""
        provided_key = request.form['key'].strip()
        chal_keys = Keys.query.filter_by(chal=chal.id).all()
        yara_results = yara_rule_tester(provided_key)
        hit_list = {}
        hit_list_correct = []
        hit_list_wrong = []
        for chal_key in chal_keys:
            for result in yara_results:
                if get_key_class(chal_key.key_type).compare(chal_key.flag, str(result)):
                    if chal_key.key_type == "static":
                        hit_list_correct.append(chal_key)
                    elif chal_key.key_type == "CTFdWrongKey":
                        hit_list_wrong.append(chal_key)
        hit_list['correct'] = hit_list_correct
        hit_list['wrong'] = hit_list_wrong
        return hit_list

    @staticmethod
    def solve(team, chal, request, flag):
        """Solve the question and put results in the Awards DB"""
        provided_key = flag
        solve = Awards(teamid=team.id, name=chal.id, value=chal.value)
        solve.description = provided_key
        # solve.category = chal_key
        db.session.add(solve)
        db.session.commit()
        db.session.close()

    @staticmethod
    def fail(team, chal, request, flag):
        """Standard fail if the question is wrong record it"""
        provided_key = flag
        wrong = WrongKeys(teamid=team.id, chalid=chal.id, ip=utils.get_ip(request), flag=provided_key)
        db.session.add(wrong)
        db.session.commit()
        db.session.close()

    def wrong(team, chal, request, flag):
        """Fail if the question is wrong record it and record the wrong answer to deduct points"""
        provided_key = flag
        wrong_value = 0
        wrong_value -= chal.value
        wrong = WrongKeys(teamid=team.id, chalid=chal.id, ip=utils.get_ip(request), flag=provided_key)
        solve = Awards(teamid=team.id, name=chal.id, value=wrong_value)
        solve.description = provided_key
        db.session.add(wrong)
        db.session.add(solve)
        db.session.commit()
        db.session.close()


def chal(chalid):
    """Custom chal function to override challenges.chal when yarachallenge is used"""
    if utils.ctf_ended() and not utils.view_after_ctf():
        abort(403)
    if not utils.user_can_view_challenges():
        return redirect(url_for('auth.login', next=request.path))
    if (utils.authed() and utils.is_verified() and (utils.ctf_started() or utils.view_after_ctf())) or utils.is_admin():
        team = Teams.query.filter_by(id=session['id']).first()
        fails = WrongKeys.query.filter_by(teamid=session['id'], chalid=chalid).count()
        logger = logging.getLogger('keys')
        data = (time.strftime("%m/%d/%Y %X"), session['username'].encode('utf-8'), request.form['key'].encode('utf-8'), utils.get_kpm(session['id']))
        print("[{0}] {1} submitted {2} with kpm {3}".format(*data))

        chal = Challenges.query.filter_by(id=chalid).first_or_404()
        chal_class = get_chal_class(chal.type)

        # Anti-bruteforce / submitting keys too quickly
        if utils.get_kpm(session['id']) > 10:
            if utils.ctftime():
                chal_class.fail(team=team, chal=chal, request=request)
            logger.warning("[{0}] {1} submitted {2} with kpm {3} [TOO FAST]".format(*data))
            # return '3' # Submitting too fast
            return jsonify({'status': 3, 'message': "You're submitting keys too fast. Slow down."})
        if str(chal.type) == 'yarachallenge':
            solves = Awards.query.filter_by(teamid=session['id'], name=chalid,
                                            description="".strip()).first()
            try:
                flag_value = solves.description
            except AttributeError:
                flag_value = ""
            # Challenge not solved yet
            if request.form['key'].strip() != flag_value or not solves:
                chal = Challenges.query.filter_by(id=chalid).first_or_404()
                provided_key = request.form['key'].strip()
                saved_keys = Keys.query.filter_by(chal=chal.id).all()

                # Hit max attempts
                max_tries = chal.max_attempts
                if max_tries and fails >= max_tries > 0:
                    return jsonify({
                        'status': 0,
                        'message': "You have 0 tries remaining"
                    })
                hit_list_return = chal_class.attempt(chal, request)
                answer_return_list = []
                # status, message = chal_class.attempt(chal, request)
                if hit_list_return['correct'] or hit_list_return['wrong'] is not []:
                    for value_in_correct_hits in hit_list_return['correct']:
                        if utils.ctftime() or utils.is_admin():
                            flag = value_in_correct_hits.flag
                            solves = Awards.query.filter_by(teamid=session['id'], name=chalid,
                                                            description=flag.strip()).first()
                            if solves is None:
                                flag = value_in_correct_hits.flag
                                chal_class.solve(team=team, chal=chal, request=request, flag=flag)
                                answer_return_list.append(flag)
                            #db.session.close()
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                    for value_in_wrong_hits in hit_list_return['wrong']:
                        flag = value_in_wrong_hits.flag
                        solves = Awards.query.filter_by(teamid=session['id'], name=chalid,
                                                        description=flag.strip()).first()
                        if solves is None:
                            flag = value_in_wrong_hits.flag
                            chal_class.wrong(team=team, chal=chal, request=request, flag=flag)
                            answer_return_list.append(flag)
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [Fail]".format(*data))
                    return jsonify({'status': 1, 'message': str(answer_return_list)})

                else:
                    message = "Nothing found"
                    if utils.ctftime() or utils.is_admin():
                        chal_class.fail(team=team, chal=chal, request=request)
                    logger.info("[{0}] {1} submitted {2} with kpm {3} [WRONG]".format(*data))
                    # return '0' # key was wrong
                    if max_tries:
                        attempts_left = max_tries - fails - 1  # Off by one since fails has changed since it was gotten
                        tries_str = 'tries'
                        if attempts_left == 1:
                            tries_str = 'try'
                        if message[-1] not in '!().;?[]\{\}':  # Add a punctuation mark if there isn't one
                            message = message + '.'
                        return jsonify({'status': 0, 'message': '{} You have {} {} remaining.'.format(message, attempts_left, tries_str)})
                    else:
                        return jsonify({'status': 0, 'message': message})
        else:
            solves = Awards.query.filter_by(teamid=session['id'], name=chalid,
                                            description=request.form['key'].strip()).first()
            try:
                flag_value = solves.description
            except AttributeError:
                flag_value = ""
            # Challange not solved yet
            if request.form['key'].strip() != flag_value or not solves:
                chal = Challenges.query.filter_by(id=chalid).first_or_404()
                provided_key = request.form['key'].strip()
                saved_keys = Keys.query.filter_by(chal=chal.id).all()

                # Hit max attempts
                max_tries = chal.max_attempts
                if max_tries and fails >= max_tries > 0:
                    return jsonify({
                        'status': 0,
                        'message': "You have 0 tries remaining"
                    })

                status, message = chal_class.attempt(chal, request)
                if status:  # The challenge plugin says the input is right
                    if utils.ctftime() or utils.is_admin():
                        chal_class.solve(team=team, chal=chal, request=request)
                    logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                    return jsonify({'status': 1, 'message': message})
                elif message == "Failed Attempt":
                    if utils.ctftime() or utils.is_admin():
                        chal_class.wrong(team=team, chal=chal, request=request)
                    logger.info("[{0}] {1} submitted {2} with kpm {3} [Failed Attempt]".format(*data))
                    return jsonify({'status': 1, 'message': message})
                else:  # The challenge plugin says the input is wrong
                    if utils.ctftime() or utils.is_admin():
                        chal_class.fail(team=team, chal=chal, request=request)
                    logger.info("[{0}] {1} submitted {2} with kpm {3} [WRONG]".format(*data))
                    # return '0' # key was wrong
                    if max_tries:
                        attempts_left = max_tries - fails - 1  # Off by one since fails has changed since it was gotten
                        tries_str = 'tries'
                        if attempts_left == 1:
                            tries_str = 'try'
                        if message[-1] not in '!().;?[]\{\}':  # Add a punctuation mark if there isn't one
                            message = message + '.'
                        return jsonify({'status': 0,
                                        'message': '{} You have {} {} remaining.'.format(message, attempts_left,
                                                                                         tries_str)})

        # Challenge already solved

    else:
        return jsonify({
            'status': -1,
            'message': "You must be logged in to solve a challenge"
        })



def yara_rule_tester(provided_key):
    results = []
    try:
        rules = yara.compile(source=provided_key)
        malz_path = os.listdir('CTFd/plugins/CTFd-yarachallenge/assets/malware')
        for file_names in malz_path:
            test_file = ('CTFd/plugins/CTFd-yarachallenge/assets/malware/' + file_names)
            matches = rules.match(test_file)
            if matches:
                match_name = str(file_names)
                results.append(match_name)
    except Exception as e:
        logging.warning("Not a valid Answer" + str(e))
        return results
    return results


def load(app):
    """load overrides for yarachallenge plugin to work properly"""
    register_plugin_assets_directory(app, base_path='/plugins/CTFd-yarachallenge/assets/')
    challenges.CHALLENGE_CLASSES["yarachallenge"] = YaraChallenge
    app.view_functions['challenges.chal'] = chal
    app.view_functions['challenges.get_chal_class'] = get_chal_class
