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


class CTFdYaraChallenge(challenges.BaseChallenge):
    """yarachallenge allows right and wrong answers and leaves the question open"""
    id = "yarachallenge"
    name = "yarachallenge"

    templates = {  # Handlebars templates used for each aspect of challenge editing & viewing
        'create': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-create.njk',
        'update': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-update.njk',
        'modal': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-modal.njk',
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        'create': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-create.js',
        'update': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-update.js',
        'modal': '/plugins/CTFd-yarachallenge/assets/yarachallenge-challenge-modal.js',
    }

    @staticmethod
    def create(request):
        """
        This method is used to process the challenge creation request.

        :param request:
        :return:
        """
        files = request.files.getlist('files[]')
        # Create challenge
        chal = YaraChallenge(
            name=request.form['name'],
            description=request.form['description'],
            value=request.form['value'],
            category=request.form['category'],
            type=request.form['chaltype']
        )

        if 'hidden' in request.form:
            chal.hidden = True
        else:
            chal.hidden = False

        max_attempts = request.form.get('max_attempts')
        if max_attempts and max_attempts.isdigit():
            chal.max_attempts = int(max_attempts)

        db.session.add(chal)
        db.session.commit()

        flag = Keys(chal.id, request.form['key'], request.form['key_type[0]'])
        if request.form.get('keydata'):
            flag.data = request.form.get('keydata')
        db.session.add(flag)

        db.session.commit()

        for f in files:
            utils.upload_file(file=f, chalid=chal.id)

        db.session.commit()

    @staticmethod
    def update(challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.

        :param challenge:
        :param request:
        :return:
        """
        challenge = YaraChallenge.query.filter_by(id=challenge.id).first()
        challenge.name = request.form['name']
        challenge.description = request.form['description']
        challenge.value = int(request.form.get('value', 0)) if request.form.get('value', 0) else 0
        challenge.max_attempts = int(request.form.get('max_attempts', 0)) if request.form.get('max_attempts', 0) else 0
        challenge.category = request.form['category']
        challenge.hidden = 'hidden' in request.form
        db.session.commit()
        db.session.close()

    @staticmethod
    def read(challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        challenge = YaraChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'description': challenge.description,
            'category': challenge.category,
            'hidden': challenge.hidden,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': CTFdYaraChallenge.id,
                'name': CTFdYaraChallenge.name,
                'templates': CTFdYaraChallenge.templates,
                'scripts': CTFdYaraChallenge.scripts,
            }
        }
        return challenge, data

    @staticmethod
    def attempt(chal, request):
        """Attempt the user answer to see if it's right"""
        provided_key = request.form['key'].strip()
        chal_keys = Keys.query.filter_by(chal=chal.id).all()
        yara_results = yara_rule_tester(provided_key)
        result_type = {}
        for result in yara_results:

            solves = Awards.query.filter_by(teamid=session['id'], name=chal.id, description=result.strip()).first()
            try:
                flag_value = str(solves.description)
            except AttributeError:
                flag_value = ""
            if result != flag_value and not solves:
                for chal_key in chal_keys:
                    if result == chal_key.flag:
                        result_type[result] = chal_key.type
                    # Challenge not solved yet
                if result_type[result] == "correct":
                    solve = Awards(teamid=session['id'], name=chal.id, value=chal.value)
                    solve.description = result
                    db.session.add(solve)
                    db.session.commit()
                elif result_type[result] == "wrong":
                    wrong_value = 0
                    wrong_value -= chal.value
                    wrong = WrongKeys(teamid=session['id'], chalid=chal.id,
                                      ip=utils.get_ip(request), flag=result)
                    solve = Awards(teamid=session['id'], name=chal.id, value=wrong_value)
                    solve.description = result
                    db.session.add(wrong)
                    db.session.add(solve)
                    db.session.commit()
        db.session.close()
        return False, "Nothing"

    @staticmethod
    def solve(team, chal, request):
        """This method is not used"""
    @staticmethod
    def fail(team, chal, request):
        """This method is not used"""


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


class YaraChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'yarachallenge'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    initial = db.Column(db.Integer)

    def __init__(self, name, description, value, category, type='yarachallenge'):
        self.name = name
        self.description = description
        self.value = value
        self.initial = value
        self.category = category
        self.type = type


def load(app):
    """load overrides for yarachallenge plugin to work properly"""
    app.db.create_all()
    register_plugin_assets_directory(app, base_path='/plugins/CTFd-yarachallenge/assets/')
    challenges.CHALLENGE_CLASSES["yarachallenge"] = CTFdYaraChallenge
    app.view_functions['challenges.get_chal_class'] = get_chal_class
