from config import configure_app, initialize_app, app_logger, db, redis_client
from flask import render_template, request, redirect, url_for, jsonify, send_from_directory, Response, flash, g, has_request_context
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from Forms import RegistrationForm, LoginForm, ChangePasswordForm
from Models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from celery_config import make_celery, celery_logger
from celery.exceptions import Ignore
import json
import subprocess
import os
import sys
from datetime import datetime
import redis
import uuid
from itsdangerous import URLSafeTimedSerializer
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from attackcti import attack_client

app = configure_app()
celery = make_celery(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

initialize_app()

def send_confirmation_email(user_email, confirmation_url):
    with open("static/email/verify_email_template.html", 'r') as file:
        html_content = file.read()

    html_content = html_content.replace('{{ url }}', confirmation_url)

    message = Mail(
        from_email=app.config['SENDGRID_FROM_EMAIL'],
        to_emails=user_email,
        subject='Confirm your email',
        html_content=html_content
    )

    try:
        sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
        app_logger.info(f"Send out email with response code: {response.status_code}")
    except Exception as e:
        print(e.message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        
        token = serializer.dumps(new_user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
        url = url_for('confirm_email', token=token, _external=True)
        
        send_confirmation_email(new_user.email, url)

        flash('Please check your email to confirm your registration.', 'warning')
    elif form.is_submitted():
        flash('Form not valid!', 'danger')
        app_logger.info(f"errors: {form.errors}")
    return render_template('register.html', title='Register', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user
        if user and check_password_hash(user.password, form.old_password.data):
            user.password = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password provided.', 'danger')
    return render_template('change_password.html', title='Change Password', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        return 'The confirmation link is invalid or has expired.', 400

    user = User.query.filter_by(email=email).first_or_404()
    if not user.email_verified:
        user.email_verified = True
        db.session.commit()
        flash('Your email has been confirmed.', 'success')
    else:
        flash('Your email has already been confirmed.', 'warning')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def is_authorized(run):
    if current_user.is_authenticated and (str(current_user.get_id()) == str(run['created_by']['id']) or current_user.admin):
        return True
    return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/api/last-cache-check')
def file_modification_time():
    try:
        mod_time = os.path.getmtime('scripts/framework/cache/full_mapping.json')
        formatted_time = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
        return jsonify({"status": "success", "mod_time": formatted_time})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File not found"}), 404

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/about-sior')
def about_sior():
    return render_template('about_sior.html')

@app.route('/get_email')
def get_email():
    return jsonify(email='r.dossantos@fh-muenster.de')

@app.route('/api/runs')
def api_runs():
    try:
        runs = []
        keys = redis_client.keys(pattern="run-*")
        for key in keys:
            run_metadata_json = redis_client.get(key)
            if run_metadata_json:
                run_metadata = json.loads(run_metadata_json)
                if run_metadata and run_metadata.get('status') == 'COMPLETED':
                    run_metadata.setdefault('created_run', 'N/A')
                    run_metadata.setdefault('created_by', {'username': 'Unknown'})
                    run_metadata.setdefault('interrelation_keywords_and_groups', 'N/A'),
                    run_metadata.setdefault('keywords', [])
                    run_metadata.setdefault('interrelation_keywords', 'N/A')
                    run_metadata.setdefault('groups', [])
                    run_metadata.setdefault('interrelation_groups', 'N/A')
                    run_metadata.setdefault('stats', {
                        'total_used_techniques': 0,
                        'unique_responses': 0,
                        'unique_detections': 0,
                        'unique_tests': 0
                    }),
                    run_metadata['is_authorized'] = is_authorized(run_metadata)

                    runs.append(run_metadata)
        return jsonify(runs)
    except Exception as e:
        app_logger.error(f"Failed to load runs data: {str(e)}")
        return jsonify({'status': 'error', 'error': 'Failed to load data'}), 500

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/groups')
def get_groups():
    search_query = request.args.get('search', '').lower()
    groups_data = redis_client.get('all-groups')
    
    if groups_data:
        groups = json.loads(groups_data)
        filtered_groups = [
            group for group in groups 
            # group name is always part of aliases
            if any(search_query in alias.lower() for alias in group.get('aliases', []))
        ]
        return jsonify(filtered_groups)
    else:
        return jsonify([])

@app.route('/tasks')
@login_required
def get_tasks():
    try:
        app_logger.debug("Getting all tasks")
        i = celery.control.inspect()

        active_tasks = i.active() or {}

        all_tasks = {
            "active": active_tasks
        }

        task_info = []

        for _, tasks_by_worker in all_tasks.items():
            for _, tasks in tasks_by_worker.items():
                for task in tasks:
                    task_id = task['id']
                    
                    if task['args'][0]:
                        task_info.append({
                            'id': task_id,
                            'state': 'CACHE UPDATING',
                            "created_run": datetime.fromtimestamp(task['time_start']).strftime("%d-%m-%Y %H:%M:%S")
                        })


        keys = redis_client.keys(pattern="status-*")
        for key in keys:
            update_data = redis_client.get(key)
            if update_data:
                update_json = json.loads(update_data)
                
            task_info.append({
                'id': update_json['id'],
                'state': update_json['state'],
                'created_run': update_json['created_run']
            })

        return jsonify(task_info)
    except Exception as e:
        exc_type, exc_base, exc_trace = sys.exc_info()
        app_logger.error(f"Failed to get tasks: {str(e)} - {exc_type} - {exc_base} - {exc_trace}")
        return jsonify([]), 500

@app.route('/run-status/<task_id>', methods=['GET'])
@login_required
def run_status(task_id):
    task = run_script_task.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {
            'state': task.state,
            'status': 'Pending...'
        }
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'status': task.info.get('status', '')
        }
    else:
        response = {
            'state': task.state,
            'status': str(task.info),
        }

    return jsonify(response)



def get_technique_data_by_id(technique_id, task_id=None):
    """ Retrieve a technique by its ID from Redis and merge with task-specific data if provided. """
    try:
        technique_json = redis_client.get(f"technique-data-{technique_id}")
        metadata_json = redis_client.get(f"run-{task_id}")
        if technique_json is not None:
            technique = json.loads(technique_json)
            metadata = None
            if task_id:
                task_techniques_json = redis_client.get(f"techniques-run-{task_id}")
                if task_techniques_json is not None and metadata_json is not None:
                    task_techniques = json.loads(task_techniques_json)
                    metadata = json.loads(metadata_json)
                    for t in task_techniques:
                        if t['technique_id'] == technique_id and 'usage_references' in t:
                            technique['usage_references'] = t['usage_references']
            if metadata is None:
                app_logger.info("metadata None")
            return {'metadata': metadata, 'technique': technique}
        else:
            app_logger.warning(f"Could not find technique-data-{technique_id}")
            return None
    except redis.RedisError as e:
        app_logger.error(f"Error fetching technique from Redis: {str(e)}")
        return None


@app.route('/technique-details/<technique_id>/')
@app.route('/technique-details/<technique_id>/<task_id>')
def technique_details(technique_id, task_id=None):
    technique_data = get_technique_data_by_id(technique_id, task_id)
    if technique_data is not None:
        return render_template('technique_details_page.html', technique_data=technique_data)
    else:
        return render_template('error_page.html', error="Technique not found"), 404


@celery.task(bind=True, rate_limit='1/h')
def run_cache_full_mapping(self, user):
    celery_logger.info(f"Starting updating cache by {user['username']}")
    command = [
        'python3',
        '-u',
        'scripts/framework/main.py',
        '--fullmapping'
    ]
    try:
        celery_logger.info(f"Run sync started by user {user['username']}")
        subprocess.run(command, stdin=subprocess.PIPE, text=True, check=True)

        with open("scripts/framework/cache/full_mapping.json", 'r') as file:
            full_mapping = json.load(file)

        for technique in full_mapping['techniques']:
            filtered_technique = {key: technique[key] for key in [
                'type', 'id', 'technique_id', 'parent_id', 'kill_chain_phases', 'name', 'description', 
                'all_references', 'group_references', 'detections', 'mitigations', 
                'responses', 'tests', 'groups'] if key in technique}

            redis_client.set(f"technique-data-{filtered_technique['technique_id']}", json.dumps(filtered_technique))
            
        with open("scripts/framework/cache/all_groups.json", 'r') as file_group:
            all_groups = json.load(file_group)
            
            redis_client.set(f"all-groups", json.dumps(all_groups))

        task_object = {
            'id': self.request.id,
            'state': 'CACHE UPDATING DONE',
            "created_run": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        }
        
        redis_client.set(f"status-{self.request.id}", json.dumps(task_object))

    except subprocess.CalledProcessError as e:
        self.update_state(
            state='FAILURE',
            meta={'exc_type': type(e).__name__, 'exc_message': str(e)}
        )
        raise Ignore()

@app.route('/api/run-cache')
@login_required
def run_cache():
    if current_user.is_authenticated and current_user.admin:
        query_user = User.query.get(current_user.get_id())
        
        user = {
            "id": query_user.id,
            "username": query_user.username,
            "admin": query_user.admin
        }
        task = run_cache_full_mapping.delay(user)
        
        return jsonify({ 'task_id': task.id }), 202
    else:
        return jsonify({}), 403


@celery.task(bind=True, rate_limit='10/m')
def run_script_task(self, interrelation_keywords_and_groups, keywords, interrelation_keywords, groups, interrelation_groups, user):
    def validate_keywords(keywords):
        import re
        for keyword in keywords:
            if not (re.match(r'^[a-zA-Z0-9, ]+$', keyword) or keywords[0] == ''):
                redis_client.delete(f"celery-task-{self.request.id}")
                return False
        return True

    def validate_interrelation(interrelation):
        allowed_interrelations = {'AND', 'OR', 'SINGLE'}
        redis_client.delete(f"celery-task-{self.request.id}")
        return interrelation in allowed_interrelations

    def validate_groups(groups):
        import re
        for group in groups:
            if not (re.match(r'^[a-zA-Z0-9, \-]+$', group) or groups[0] == ''):
                redis_client.delete(f"celery-task-{self.request.id}")
                return False
        return True

    if not validate_keywords(keywords):
        redis_client.delete(f"celery-task-{self.request.id}")
        return {'status': 'failed', 'message': f"Wrong keywords {keywords}"}

    if not validate_groups(groups):
        redis_client.delete(f"celery-task-{self.request.id}")
        return {'status': 'failed', 'message': f"Wrong groups {groups}"}

    if not validate_interrelation(interrelation_keywords_and_groups):
        return {'status': 'failed', 'message': f"Wrong interrelation_keywords_and_groups {interrelation_keywords_and_groups}"}
    if not validate_interrelation(interrelation_keywords):
        return {'status': 'failed', 'message': f"Wrong interrelation_keywords {interrelation_keywords}"}
    if not validate_interrelation(interrelation_groups):
        return {'status': 'failed', 'message': f"Wrong interrelation_groups {interrelation_groups}"}


    unique_id = str(uuid.uuid4())
    output_path = f"/tmp/{unique_id}.json"
    
    command = [
        'python3',
        '-u',
        'scripts/framework/main.py',
        '--interrelationkeywordsandgroups', interrelation_keywords_and_groups,
        '--interrelationkeywords', interrelation_keywords,
        '--interrelationgroups', interrelation_groups,
        '--outputpath',
        output_path
    ]
    
    if len(keywords) > 0:
        command.extend(['--keywords', *keywords])

    if len(groups) > 0:
        command.extend(['--groups', *groups])

    try:
        celery_logger.info(f"Task started by user {user['username']}")
        subprocess.run(command, stdin=subprocess.PIPE, text=True, check=True)
        with open(output_path, 'r') as output_file:
            output = output_file.read()
            result_data = json.loads(output)
            techniques_task_specific = [{
                'technique_id': tech['technique_id'],
                'stats': tech['stats'],
                'usage_references': tech['usage_references'],
                'name': tech['name']
            } for tech in result_data['techniques']]

            metadata = {
                'task_id': self.request.id,
                'status': 'COMPLETED',
                'created_by': user,
                'interrelation_keywords_and_groups': interrelation_keywords_and_groups,
                'keywords': keywords,
                'interrelation_keywords': interrelation_keywords,
                'groups': groups,
                'interrelation_groups': interrelation_groups,
                'created_run': datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                'techniques': [tech['technique_id'] for tech in techniques_task_specific],
                'stats': result_data['stats']
            }

            redis_client.set(f"run-{self.request.id}", json.dumps(metadata))
            redis_client.set(f"techniques-run-{self.request.id}", json.dumps(techniques_task_specific))
            celery_logger.info(f"Stored task and techniques data for {self.request.id}")
            
            return metadata

    except subprocess.CalledProcessError as e:
        if e.returncode == 3:
            metadata = {
                'task_id': self.request.id,
                'status': 'NO_TECHNIQUES',
                'created_by': user,
                'interrelation_keywords_and_groups': interrelation_keywords_and_groups,
                'keywords': keywords,
                'interrelation_keywords': interrelation_keywords,
                'groups': groups,
                'interrelation_groups': interrelation_groups,
                'created_run': datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                'techniques': [],
                'stats': []
            }

            redis_client.set(f"run-{self.request.id}", json.dumps(metadata))
            celery_logger.info(f"Did not store techniques data, because no techniques where found for {self.request.id}")
            
            return metadata
        else:
            self.update_state(
                state='FAILURE',
                meta={'exc_type': type(e).__name__, 'exc_message': str(e)}
            )
            raise Ignore()
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)

@app.route('/run-script', methods=['POST'])
@login_required
def run_script():
    keywords = request.form.getlist('keywords_input')
    app_logger.info(f"keywords: {request.form}")
    groups = request.form.getlist('groupSelect')

    if len(keywords) == 0 and len(groups) == 0:
        return jsonify({
            'status': 'PARAMETERS_EMPTY'
        }), 200
    
    if len(keywords) < 2:
        interrelation_keywords = 'SINGLE'
    else:
        interrelation_keywords = request.form['interrelation_keywords']
    
    if len(groups) < 2:
        interrelation_groups = 'SINGLE'
    else:
        interrelation_groups = request.form['interrelation_groups']
        
    if len(keywords) == 0 or len(groups) == 0:
        interrelation_keywords_and_groups = 'SINGLE'
    else:
        interrelation_keywords_and_groups = request.form['interrelation_keywords_and_groups']
        
    user_id = current_user.get_id()
    username = User.query.get(user_id).username
    user = {
        "id": user_id,
        "username": username
    }

    if not request.form.get('force_run', False):
        existing_run = None
        for run_key in redis_client.keys('run-*'):
            run = json.loads(redis_client.get(run_key))
            
            run_keywords = set(run['keywords'])
            run_groups = set(run['groups'])
            keywords = set(keywords)
            groups = set(groups)

            if (run_keywords == keywords and 
                run_groups == groups and 
                run['interrelation_keywords'] == interrelation_keywords and 
                run['interrelation_groups'] == interrelation_groups and 
                run['interrelation_keywords_and_groups'] == interrelation_keywords_and_groups):
                existing_run = run
                break
        
        if existing_run:
            return jsonify({
                'status': 'EXIST',
                'created_run': existing_run['created_run'],
                'run': existing_run
            }), 200
    
    
    app_logger.info(f"User {user['username']} starting run_script for {interrelation_keywords_and_groups}, {list(keywords)}, {interrelation_keywords} and {list(groups)}, {interrelation_groups}")
    
    task = run_script_task.delay(interrelation_keywords_and_groups, list(keywords), interrelation_keywords, list(groups), interrelation_groups, user)
    
    return jsonify({ 'task_id': task.id, 'queue_signal': '!' }), 202


def find_color_for_count(colors, count):
    keys = sorted(int(key) for key in colors if key.isdigit())
    
    selected_key = None
    for key in keys:
        if key <= count:
            selected_key = key
        else:
            break

    if selected_key is None or count > max(keys):
        selected_key = 'more'
    
    return colors[str(selected_key)]['color']


@app.route('/download-run/<task_id>', methods=['GET'])
def download_run(task_id):
    metadata_json = redis_client.get(f"run-{task_id}")
    result_json = redis_client.get(f"techniques-run-{task_id}")
    if not metadata_json or not result_json:
        app_logger.error(f"Could not find metadata or techniques for {task_id}")
        return redirect(url_for('dashboard'))

    full_data = json.loads(metadata_json)
    techniques = json.loads(result_json)
    
    full_techniques = []
    for technique in techniques:
        full_techniques.append(get_technique_data_by_id(technique['technique_id'], task_id)['technique'])
    
    full_data['techniques'] = full_techniques
    
    response = Response(
        json.dumps(full_data, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': f"attachment;filename=SIOR_{full_data['interrelation_keywords']}-{'-'.join(full_data['keywords'])}_{full_data['interrelation_groups']}-{'-'.join(full_data['groups'])}.json"}
    )
    return response

def fetch_all_techniques(tech_path="scripts/framework/cache/all_techniques.json", no_cache=False):
    if os.path.exists(tech_path) and not no_cache:
        app_logger.info("Loading techniques from local JSON file.")
        with open(tech_path, 'r') as json_file:
            _all_techniques = json.load(json_file)
            techniques_list = []
            for t in _all_techniques:
                technique_info = {
                    "score": 0,
                    "technique_id": t['technique_id'],
                    "enabled": False
                }
                techniques_list.append(technique_info)
    else:
        app_logger.info("Retrieving all techniques from ATT&CK server")
        try:
            lift = attack_client()
        except Exception as e:
            app_logger.warning(f"Could not connect to cti-taxii.mitre.com : {str(e)}")
            app_logger.info("Using local cti repository")
            try:
                local_paths = {
                    "enterprise": "resources/cti/enterprise-attack",
                    "mobile": "resources/cti/mobile-attack",
                    "ics": "resources/cti/ics-attack"
                }
                lift = attack_client(local_paths=local_paths)
            except Exception as e:
                app_logger.error(f"Could not use local cti repository : {str(e)}")
                exit(1)
        try:
            _all_techniques = lift.get_techniques(enrich_data_sources=False)
        except Exception as e:
            app_logger.error(f"Could not download techniques from ATT&CK server: {str(e)}")
            exit(2)
        app_logger.info("Finished retrieving all techniques")
        techniques_list = []
        for t in _all_techniques:
            technique_info = {
                "score": 0,
                "technique_id": t['external_references'][0]['external_id'],
                "enabled": False
            }
            techniques_list.append(technique_info)
        with open(tech_path, 'w+') as json_file:
            json.dump(techniques_list, json_file)
        app_logger.info(f"Techniques saved to {tech_path}")
        
    return techniques_list

def process_json_file(file, all_techniques):
    techniques_count = {}

    result_data = {
        "description": "Enterprise techniques",
        "name": "Heat-Map",
        "domain": "enterprise-attack",
        "versions": {
            "layer": "4.5",
            "attack": "15",
            "navigator": "5.1.0"
        },
        "gradient": {
            "colors": ["#FAAAAA", "#420000"],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [],
        "techniques": [],
        "layout": {
            "expandedSubtechniques": "annotated"
        },
        "hideDisabled": True
    }

    # Create a set of technique IDs from the imported JSON file
    file_techniques = file.get("techniques", [])
    imported_technique_ids = [file['technique'].get("technique_id") for file in file_techniques if "technique_id" in file['technique']]
    
    app_logger.info(len(file_techniques))
    app_logger.info(file_techniques[0].keys())
    app_logger.info(file_techniques[0]["technique"].keys())
    
    total_elements = len(file.get("keywords", [])) + len(file.get("groups", []))

    # Process each technique in the imported file
    for file_technique in file_techniques:
        technique = file_technique.get('technique')
        technique_id = technique.get("technique_id")
        
        if not technique_id:
            app_logger.warning(f"Could not find technique_id for {technique.keys()}")
            continue

        if technique_id in techniques_count:
            techniques_count[technique_id]["count"] += 1
        else:
            techniques_count[technique_id] = {"count": 1}

        score = techniques_count[technique_id]['count'] / total_elements if total_elements > 0 else 1

        detections = technique.get("detections", {})
        responses = technique.get("responses", {})
        tests = technique.get("tests", {})
        detections_sum = len(detections.get("att&ck", [])) + len(detections.get("d3fend", [])) + len(detections.get("sigma", []))
        responses_sum = len(responses.get("d3fend", [])) + len(responses.get("guardsight", []))
        tests_sum = len(tests.get("atomic", []))

        technique_entry = {
            "techniqueID": technique_id,
            "comment": f"{techniques_count[technique_id]['count']} times",
            "showSubtechniques": technique.get("showSubtechniques", False),
            "score": score,
            "enabled": True,
            "detectionsSum": detections_sum,
            "responsesSum": responses_sum,
            "testsSum": tests_sum
        }
        app_logger.info(technique_entry)
        result_data["techniques"].append(technique_entry)

    # Add techniques from the ATT&CK framework that were not in the imported JSON
    for attack_technique in all_techniques:
        technique_id = attack_technique["technique_id"]
        if technique_id not in imported_technique_ids:
            technique_entry = {
                "techniqueID": technique_id,
                "comment": "Not used in this context",
                "score": 0,
                "enabled": False
            }
            result_data["techniques"].append(technique_entry)
        else:
            app_logger.info(f"NOT IN {technique_id}")
    
    return result_data

def create_detection_response_test_heatmap(result_data):
    heatmap_data = {
        "description": "Techniques with Detections, Responses, and Tests",
        "name": "Detection-Response-Test Heat-Map",
        "domain": "enterprise-attack",
        "versions": {
            "layer": "4.5",
            "attack": "15",
            "navigator": "5.0.1"
        },
        "gradient": {
            "colors": ["#FAAAAA", "#420000"],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "One category of detection, response, or test present",
                "color": "#FF0000"
            },
            {
                "label": "Two categories of detection, response, or test present",
                "color": "#FFFF00"
            },
            {
                "label": "All categories of detection, response, and test present",
                "color": "#00FF00"
            }
        ],
        "techniques": [],
        "layout": {
            "expandedSubtechniques": "annotated"
        },
        "hideDisabled": True
    }

    no_detection_gradient = ["#D3D3D3", "#2A2A2A"]

    for technique in result_data["techniques"]:
        technique_id = technique["techniqueID"]

        detections_sum = technique.get("detectionsSum", 0)
        responses_sum = technique.get("responsesSum", 0)
        tests_sum = technique.get("testsSum", 0)

        active_sums = sum([detections_sum > 0, responses_sum > 0, tests_sum > 0])

        if active_sums == 0:
            factor = technique.get("score", 0)
            interpolated_color = interpolate_color(no_detection_gradient[0], no_detection_gradient[1], factor)
            heatmap_entry = {
                "techniqueID": technique_id,
                "comment": technique.get("comment", "No additional data available"),
                "enabled": technique["score"] > 0,
                "color": interpolated_color
            }
        else:
            if active_sums == 1:
                color = "#FF0000"  # Red
            elif active_sums == 2:
                color = "#FFFF00"  # Yellow
            elif active_sums == 3:
                color = "#00FF00"  # Green

            heatmap_entry = {
                "techniqueID": technique_id,
                "comment": f"Detections: {detections_sum}, Responses: {responses_sum}, Tests: {tests_sum}",
                "enabled": True,
                "color": color
            }

        heatmap_data["techniques"].append(heatmap_entry)

    return heatmap_data

def interpolate_color(color1, color2, factor):
    def hex_to_rgb(hex_color):
        return tuple(int(hex_color[i:i+2], 16) for i in (1, 3, 5))

    def rgb_to_hex(rgb_color):
        return "#{:02x}{:02x}{:02x}".format(*rgb_color)

    color1_rgb = hex_to_rgb(color1)
    color2_rgb = hex_to_rgb(color2)

    interpolated_rgb = tuple(int(c1 + (c2 - c1) * factor) for c1, c2 in zip(color1_rgb, color2_rgb))
    return rgb_to_hex(interpolated_rgb)

@app.route('/download-heatmap-usage/<task_id>', methods=['GET'])
def download_heatmap_usage(task_id):
    metadata_json = redis_client.get(f"run-{task_id}")
    result_json = redis_client.get(f"techniques-run-{task_id}")
    if not metadata_json or not result_json:
        app_logger.error(f"Could not find metadata or techniques for {task_id}")
        return redirect(url_for('dashboard'))

    full_data = json.loads(metadata_json)
    techniques = json.loads(result_json)
    
    full_techniques = []
    for technique in techniques:
        full_techniques.append(get_technique_data_by_id(technique['technique_id'], task_id))
    
    full_data['techniques'] = full_techniques
    all_techniques = fetch_all_techniques()

    result_data = process_json_file(full_data, all_techniques)

    response = Response(
        json.dumps(result_data, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': f"attachment;filename=heatmap_{full_data['interrelation_keywords']}-{'-'.join(full_data['keywords'])}_{full_data['interrelation_groups']}-{'-'.join(full_data['groups'])}.json"}
    )
    app_logger.info('Exported heatmap-usage-file')
    return response

@app.route('/download-heatmap/<task_id>', methods=['GET'])
def download_heatmap(task_id):
    metadata_json = redis_client.get(f"run-{task_id}")
    result_json = redis_client.get(f"techniques-run-{task_id}")
    if not metadata_json or not result_json:
        app_logger.error(f"Could not find metadata or techniques for {task_id}")
        return redirect(url_for('dashboard'))

    full_data = json.loads(metadata_json)
    techniques = json.loads(result_json)
    
    full_techniques = []
    for technique in techniques:
        full_techniques.append(get_technique_data_by_id(technique['technique_id'], task_id))
    
    full_data['techniques'] = full_techniques
    all_techniques = fetch_all_techniques()

    result_data = process_json_file(full_data, all_techniques)
    
    heatmap_data = create_detection_response_test_heatmap(result_data)

    app_logger.info('Exported heatmap-file')
    
    response = Response(
        json.dumps(heatmap_data, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': f"attachment;filename=heatmap_SIOR_{full_data['interrelation_keywords']}-{'-'.join(full_data['keywords'])}_{full_data['interrelation_groups']}-{'-'.join(full_data['groups'])}.json"}
    )
    return response

@app.route('/task-status/<task_id>', methods=['GET'])
@login_required
def task_status(task_id):
    result = redis_client.get(task_id)
    if result:
        return jsonify(json.loads(result))
    else:
        return jsonify({"task_id": task_id, "status": "not found"}), 404


@app.route('/deletetechnique/<task_id>', methods=['POST'])
@login_required
def delete_technique(task_id):
    try:
        meta_data = redis_client.get(f"run-{task_id}")
        meta_data = json.loads(meta_data)
        if not meta_data:
            app_logger.error(f"Failed to delete result and metadata for task with ID {task_id}: Could not parse")
            return redirect(url_for('dashboard'))
        if str(current_user.get_id()) == meta_data['created_by']['id']:
            meta_data['status'] = 'DELETED'
            redis_client.delete(f"techniques-run-{task_id}")
            redis_client.delete(f"run-{task_id}")
            app_logger.info(f"Deleted result and metadata for task with ID: {task_id}")
            return jsonify({"status": "success"}), 202
        else:
            app_logger.error(f"user {meta_data['user']['id']} tried to delete run {task_id} - illegal")
            return jsonify({"status": "error", "message": f"user {meta_data['user']['id']} tried to delete run {task_id} - illegal"}), 403
    except Exception as e:
        app_logger.error(f"Failed to delete result and metadata for task with ID {task_id}: {str(e)}")
    return redirect(url_for('dashboard'))

@app.route('/techniques/<task_id>')
def display_techniques(task_id):
    try:
        metadata_json = redis_client.get(f"run-{task_id}")
        techniques_json = redis_client.get(f"techniques-run-{task_id}")

        if not metadata_json:
            app_logger.error(f"Could not find metadata for {task_id}")
            return redirect(url_for('dashboard'))

        if not techniques_json:
            app_logger.error(f"Could not find techniques for {task_id}")
            return redirect(url_for('dashboard'))


        metadata = json.loads(metadata_json)
        techniques = json.loads(techniques_json)

        return render_template('techniques.html', data={**metadata, 'techniques': techniques})
    except Exception as e:
        app_logger.error(f"Failed to display techniques for task {task_id}: {str(e)}")
        return redirect(url_for('dashboard'))

@app.after_request
def apply_csp(response):
    if response.content_type.startswith('text/html'):
        csp_script_src = (
            f"script-src 'self' "
            "https://ajax.googleapis.com "
            "https://cdnjs.cloudflare.com "
            "https://cdn.datatables.net "
            "https://cdn.jsdelivr.net "
            "https://www.google.com/recaptcha/ "
            "https://www.gstatic.com/recaptcha/ "
            "https://www.sior-helper.com/static/js/main.js "
            "https://sior-helper.com/static/js/main.js; "
        )
        csp_frame_src = (
            "frame-src 'self' "
            "https://www.google.com/recaptcha/ "
            "https://recaptcha.google.com/; "
        )
        response.headers["Content-Security-Policy"] = csp_script_src + csp_frame_src
    return response

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found.", 404

@app.errorhandler(500)
def internal_server_error(e):
    return "Internal server error.", 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')