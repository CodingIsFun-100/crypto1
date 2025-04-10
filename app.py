# -*- coding: utf-8 -*-
from flask import (Flask, request, render_template, redirect,
                   url_for, session, flash, jsonify)
import random
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
import json
import bcrypt
import sqlite3
import time

# --- Configuration ---
ENCRYPTION_KEY_FILE = 'encryption.key'
SALT_FILE = 'encryption.salt'
LOG_FILE = 'app.log.encrypted'
ADMIN_ROUTE = '/secret-admin'
DATABASE_FILE = 'seeds.db'
PANIC_FLAG_FILE = 'panic.flag' # <-- File to indicate panic mode

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Passwords / Hashes ---
# !!! Security Warning: Avoid hardcoding secrets in production !!!
ADMIN_PASSWORD_HASH ="$2b$12$CW.FnLFipKJoRyULRymod.9lv0TUA.SowC0EYk9RAWh0jk6.Hvwiu" #pass for hased salt 5y5t3mc0d3r
REACTIVATION_PASSWORD_HASH = "$2b$12$efVetLnXxuw7rndpyBevJOX5XctySs8A6Pb64m5a8gYgAosHnHsyi" #pass
ENCRYPTION_PASSWORD = "secretpasswordhere"

# --- Global Panic State ---
PANIC_MODE_ACTIVE = False # In-memory flag, set based on file at startup

# --- Encryption/Decryption Functions (Unchanged) ---
def generate_salt():
    return os.urandom(16)

def derive_key(password, salt):
    if not password: raise ValueError("Password cannot be empty for key derivation")
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def load_or_generate_key(password):
    if not password:
         logging.error("Cannot load/generate key without an encryption password.")
         return None
    if os.path.exists(ENCRYPTION_KEY_FILE) and os.path.exists(SALT_FILE):
        try:
            with open(SALT_FILE, 'rb') as f: salt = f.read()
            derived_key_for_decryption = derive_key(password, salt)
            f_decrypt = Fernet(derived_key_for_decryption)
            with open(ENCRYPTION_KEY_FILE, 'rb') as f: encrypted_stored_key = f.read()
            key_bytes = f_decrypt.decrypt(encrypted_stored_key)
            logging.info("Successfully decrypted stored encryption key.")
            return key_bytes.decode('utf-8')
        except Exception as e:
            logging.error(f"Error decrypting stored key (maybe wrong password?): {e}. Regenerating key and salt.")
    logging.warning(f"Generating new salt and encryption key. Old logs/seeds encrypted with a previous key will be unreadable.")
    salt = generate_salt()
    key_bytes = Fernet.generate_key()
    derived_key_for_storage = derive_key(password, salt)
    f_encrypt = Fernet(derived_key_for_storage)
    encrypted_key_to_store = f_encrypt.encrypt(key_bytes)
    with open(SALT_FILE, 'wb') as sf: sf.write(salt)
    with open(ENCRYPTION_KEY_FILE, 'wb') as kf: kf.write(encrypted_key_to_store)
    logging.info("New salt and encrypted key saved.")
    return key_bytes.decode('utf-8')

def encrypt_data(key, data):
    if not key: raise ValueError("Encryption key is missing")
    f = Fernet(key.encode('utf-8'))
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(key, encrypted_data):
    if not key: raise ValueError("Decryption key is missing")
    f = Fernet(key.encode('utf-8'))
    return f.decrypt(encrypted_data).decode('utf-8')

# --- Logging Functions (Unchanged) ---
def append_encrypted_log(log_file, encrypted_entry):
    try:
        with open(log_file, 'ab') as f: f.write(encrypted_entry + b'\n')
    except Exception as e:
        logging.error(f"Failed to append to log file {log_file}: {e}")

def read_encrypted_log(log_file, key):
    # Modified: Return specific message if panic mode is active
    global PANIC_MODE_ACTIVE
    if PANIC_MODE_ACTIVE:
        logging.warning("Log access denied due to active PANIC MODE.")
        return ["PANIC MODE ACTIVE - Logs are inaccessible."]

    decrypted_logs = []
    if not key:
        logging.error("Cannot read encrypted log: Decryption key is missing.")
        return ["Error: Decryption key missing."]
    if not os.path.exists(log_file):
        logging.warning(f"Log file '{log_file}' not found.")
        return decrypted_logs
    try:
        with open(log_file, 'rb') as f:
            for line_num, line in enumerate(f, 1):
                encrypted_line = line.strip()
                if encrypted_line:
                    try:
                        decrypted_logs.append(decrypt_data(key, encrypted_line))
                    except Exception as e:
                        logging.error(f"Error decrypting log entry on line {line_num}: {e}")
                        decrypted_logs.append(f"!!! Error decrypting entry (line {line_num}): {e} !!!")
    except Exception as e:
         logging.error(f"Error reading log file '{log_file}': {e}")
         decrypted_logs.append(f"!!! Error reading log file: {e} !!!")
    return decrypted_logs

# --- Database Functions for Seeds (Unchanged) ---
def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with get_db() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS deactivated_seeds (seed_value TEXT PRIMARY KEY NOT NULL)')
            conn.commit()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")

def load_deactivated_seeds_db():
    seeds = set()
    try:
        with get_db() as conn:
            cursor = conn.execute('SELECT seed_value FROM deactivated_seeds')
            seeds = {row['seed_value'] for row in cursor.fetchall()}
    except sqlite3.Error as e:
        logging.error(f"Error loading seeds from database: {e}")
    return seeds

def add_deactivated_seed_db(seed):
    try:
        with get_db() as conn:
            conn.execute('INSERT OR IGNORE INTO deactivated_seeds (seed_value) VALUES (?)', (seed,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error adding seed '{seed}' to database: {e}")

def remove_deactivated_seed_db(seed):
    try:
        with get_db() as conn:
            cursor = conn.execute('DELETE FROM deactivated_seeds WHERE seed_value = ?', (seed,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Seed '{seed}' removed from deactivated list in DB.")
                return True
            else:
                logging.warning(f"Attempted to remove seed '{seed}' from DB, but it was not found.")
                return False
    except sqlite3.Error as e:
        logging.error(f"Error removing seed '{seed}' from database: {e}")
        return False

# --- Panic Action Functions (Unchanged) ---
def clear_all_seeds_db():
    try:
        with get_db() as conn:
            cursor = conn.execute('DELETE FROM deactivated_seeds')
            conn.commit()
            logging.warning(f"PANIC ACTION: Cleared {cursor.rowcount} deactivated seeds from database.")
            return True
    except sqlite3.Error as e:
        logging.error(f"PANIC ACTION FAILED: Error clearing seeds database: {e}")
        return False

def clear_log_file(log_file_path):
    try:
        with open(log_file_path, 'wb') as f: pass
        logging.warning(f"PANIC ACTION: Cleared log file '{log_file_path}'.")
        return True
    except FileNotFoundError:
        logging.warning(f"PANIC ACTION: Log file '{log_file_path}' not found, nothing to clear.")
        return True
    except Exception as e:
        logging.error(f"PANIC ACTION FAILED: Error clearing log file '{log_file_path}': {e}")
        return False

# --- Helper: Restart Application ---
def restart_application():
    """Attempts to restart the current application using os.execv."""
    logging.warning("Attempting application restart via os.execv...")
    # Optional: Short delay
    time.sleep(1)
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        logging.error(f"os.execv failed: {e}. Manual restart required.")
        # Cannot easily return an error page here as the process might be unstable
        # This function effectively stops execution if successful

# --- Flask Application ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Initialize Database ---
init_db()

# --- Check for Panic Flag on Startup ---
if os.path.exists(PANIC_FLAG_FILE):
    PANIC_MODE_ACTIVE = True
    logging.critical(f"PANIC MODE DETECTED on startup due to flag file: {PANIC_FLAG_FILE}")
else:
    PANIC_MODE_ACTIVE = False

# --- Load Encryption Key ---
try:
    # Load key even if panic mode is active, might be needed for reset logging
    encryption_key = load_or_generate_key(ENCRYPTION_PASSWORD)
    if encryption_key:
        logging.info("Encryption key loaded or generated.")
    else:
        # Don't raise error if panic mode is active, allow app to run in limited state
        if not PANIC_MODE_ACTIVE:
            raise ValueError("Failed to obtain encryption key.")
        else:
            logging.warning("Failed to obtain encryption key, but continuing in PANIC MODE.")
except Exception as e:
    logging.critical(f"CRITICAL ERROR during key loading: {e}")
    encryption_key = None # Ensure it's None on failure

# --- Before Request Handler for Panic Mode ---
@app.before_request
def check_panic_mode():
    """Intercepts requests if panic mode is active."""
    global PANIC_MODE_ACTIVE
    if PANIC_MODE_ACTIVE:
        # Allow access ONLY to the reset route and static files
        if request.endpoint and (request.endpoint == 'reset_panic' or request.endpoint == 'static'):
            return # Allow request to proceed

        # For all other requests, log the IP and show panic screen
        ip_address = request.remote_addr
        logging.warning(f"PANIC MODE: Blocked request from IP {ip_address} to endpoint '{request.endpoint or 'N/A'}'")
        # Log attempt (might fail if key is missing)
        log_entry = f"IP: {ip_address} - Request blocked by PANIC MODE (Target: {request.path})"
        try:
            enc_log = encrypt_data(encryption_key, log_entry)
            append_encrypted_log(LOG_FILE, enc_log)
        except Exception as log_err:
            logging.error(f"Failed to log blocked request during panic: {log_err}")

        return render_template('panic.html'), 503 # Service Unavailable

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    # ... (existing index route logic, including IP logging) ...
    # Ensure panic_url and reset_url are passed to template
    ip_address = request.remote_addr

    if encryption_key is None and not PANIC_MODE_ACTIVE: # Check panic mode here too
         flash("Critical Error: Application encryption key is not configured.", "error")
         login_url = url_for('login')
         panic_url = url_for('confirm_panic')
         reset_url = url_for('reset_panic')
         return render_template('index.html', encoded_text=None, decoded_text=None, login_url=login_url, panic_url=panic_url, reset_url=reset_url), 500

    encoded_text = None
    decoded_text = None
    seed_error = None

    if request.method == 'POST':
        mode = request.form.get('mode')
        seed = request.form.get('seed', '').strip()
        text = request.form.get('text')

        if not mode or not seed or text is None:
            flash("Mode, Seed, and Text are required.", "warning")
            login_url = url_for('login')
            panic_url = url_for('confirm_panic')
            reset_url = url_for('reset_panic')
            return render_template('index.html', encoded_text=None, decoded_text=None, login_url=login_url, panic_url=panic_url, reset_url=reset_url)

        try:
            deactivated_seeds = load_deactivated_seeds_db()

            if seed in deactivated_seeds:
                seed_error = f"Seed '{seed}' has already been used and is deactivated."
                flash(seed_error, "error")
                log_entry = f"IP: {ip_address} - Attempted use of deactivated seed - Mode: {mode}, Seed: {seed}"
                try:
                    encrypted_log = encrypt_data(encryption_key, log_entry)
                    append_encrypted_log(LOG_FILE, encrypted_log)
                except ValueError as enc_err: logging.error(f"Logging failed: {enc_err}")
                logging.warning(log_entry)

                login_url = url_for('login')
                panic_url = url_for('confirm_panic')
                reset_url = url_for('reset_panic')
                return render_template('index.html', encoded_text=None, decoded_text=None, seed_error=seed_error, login_url=login_url, panic_url=panic_url, reset_url=reset_url)

            log_entry = f"IP: {ip_address} - Request received - Mode: {mode}, Seed: {seed}, Text present: {'yes' if text else 'no'}"
            try:
                encrypted_log = encrypt_data(encryption_key, log_entry)
                append_encrypted_log(LOG_FILE, encrypted_log)
            except ValueError as enc_err: logging.error(f"Logging failed: {enc_err}")
            logging.info("Request information logged.")

            try:
                random.seed(seed)
                processed_chars = []
                result_log_entry = ""

                if mode == 'encode':
                    for char in text:
                        shift = random.randint(-13, 13)
                        processed_chars.append(chr(ord(char) + shift))
                    encoded_text = "".join(processed_chars)
                    result_log_entry = f"IP: {ip_address} - Encoded with seed '{seed}' (Original text length: {len(text)})"
                    flash(f"Encoding successful with seed '{seed}'.", "success")

                elif mode == 'decode':
                    for char in text:
                        shift = random.randint(-13, 13)
                        processed_chars.append(chr(ord(char) - shift))
                    decoded_text = "".join(processed_chars)
                    result_log_entry = f"IP: {ip_address} - Decoded with seed '{seed}' (Encoded text length: {len(text)})"
                    add_deactivated_seed_db(seed)
                    flash(f"Decoding successful. Seed '{seed}' is now deactivated.", "success")
                    deactivation_log = f"IP: {ip_address} - Seed '{seed}' deactivated after decoding."
                    try:
                        enc_deactivation_log = encrypt_data(encryption_key, deactivation_log)
                        append_encrypted_log(LOG_FILE, enc_deactivation_log)
                    except ValueError as enc_err: logging.error(f"Logging failed: {enc_err}")
                    logging.info(deactivation_log)

                else:
                     flash("Invalid mode selected.", "error")
                     login_url = url_for('login')
                     panic_url = url_for('confirm_panic')
                     reset_url = url_for('reset_panic')
                     return render_template('index.html', login_url=login_url, panic_url=panic_url, reset_url=reset_url)

                if result_log_entry:
                    try:
                        encrypted_log_res = encrypt_data(encryption_key, result_log_entry)
                        append_encrypted_log(LOG_FILE, encrypted_log_res)
                        logging.info(f"{mode.capitalize()} result logged.")
                    except ValueError as enc_err:
                        logging.error(f"Logging result failed: {enc_err}")

            except Exception as e:
                logging.error(f"Error during {mode} with seed '{seed}': {e}")
                flash(f"An error occurred during {mode}. Please check the logs.", "error")
                error_log_entry = f"IP: {ip_address} - ERROR during {mode} - Seed: {seed}, Error: {e}"
                try:
                    encrypted_error_log = encrypt_data(encryption_key, error_log_entry)
                    append_encrypted_log(LOG_FILE, encrypted_error_log)
                except ValueError as enc_err:
                    logging.error(f"Logging error failed: {enc_err}")

        except Exception as e:
             logging.error(f"Critical error during request processing: {e}")
             flash("A critical error occurred. Please contact the administrator.", "error")

    login_url = url_for('login')
    panic_url = url_for('confirm_panic')
    reset_url = url_for('reset_panic')
    return render_template('index.html',
                           encoded_text=encoded_text,
                           decoded_text=decoded_text,
                           seed_error=seed_error,
                           login_url=login_url,
                           panic_url=panic_url,
                           reset_url=reset_url) # Pass reset URL


@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (existing login route logic with referrer check) ...
    # Allow access if coming from reset page too
    referrer = request.referrer
    is_from_index = referrer and referrer.endswith(url_for('index'))
    is_from_panic = referrer and referrer.endswith(url_for('confirm_panic'))
    is_from_reset = referrer and referrer.endswith(url_for('reset_panic')) # Allow from reset

    if request.method == 'GET' and not is_from_index and not is_from_panic and not is_from_reset:
        flash("Please use the secret button on the main page to access login.", "warning")
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        password_attempt = request.form['password']
        try:
            if bcrypt.checkpw(password_attempt.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8')):
                session['logged_in'] = True
                logging.info("Admin login successful.")
                flash("Login successful!", "success")
                return redirect(url_for('secret_admin_route'))
            else:
                error = 'Invalid password'
                logging.warning(f"Failed admin login attempt from IP: {request.remote_addr}")
                flash("Invalid password.", "error")
        except ValueError:
             logging.error("Admin login check failed: Invalid hash format stored.")
             flash("Login configuration error.", "error")
             error = "Login temporarily unavailable."

    return render_template('login.html', error=error)


@app.route(ADMIN_ROUTE)
def secret_admin_route():
    global PANIC_MODE_ACTIVE # Access global flag
    if not session.get('logged_in'):
        flash("You need to be logged in to view this page.", "warning")
        return redirect(url_for('login'))

    # Read logs (will return error message if panic is active)
    decrypted_logs = read_encrypted_log(LOG_FILE, encryption_key)
    if PANIC_MODE_ACTIVE:
        flash("PANIC MODE ACTIVE - Logs are inaccessible.", "danger")

    # Load seeds (still useful to see even in panic mode maybe?)
    deactivated_seeds = load_deactivated_seeds_db()

    return render_template('secret_admin.html',
                           logs=decrypted_logs,
                           deactivated_seeds=sorted(list(deactivated_seeds)),
                           panic_mode=PANIC_MODE_ACTIVE) # Pass panic status to template


@app.route('/reactivate_seed', methods=['POST'])
def reactivate_seed():
    # ... (existing reactivate_seed logic, including IP logging) ...
    # Add check for panic mode? Maybe allow reactivation even in panic? For now, allow.
    if not session.get('logged_in'):
        flash("Authentication required.", "error")
        return redirect(url_for('login'))

    seed_to_reactivate = request.form.get('seed')
    reactivation_password_attempt = request.form.get('password')

    if not seed_to_reactivate or not reactivation_password_attempt:
        flash("Seed and Reactivation Password are required.", "warning")
        return redirect(url_for('secret_admin_route'))

    try:
        if bcrypt.checkpw(reactivation_password_attempt.encode('utf-8'), REACTIVATION_PASSWORD_HASH.encode('utf-8')):
            if remove_deactivated_seed_db(seed_to_reactivate):
                 flash(f"Seed '{seed_to_reactivate}' has been reactivated successfully!", "success")
                 log_entry = f"IP: {request.remote_addr} - Admin reactivated seed '{seed_to_reactivate}'."
                 try:
                     enc_log = encrypt_data(encryption_key, log_entry)
                     append_encrypted_log(LOG_FILE, enc_log)
                 except ValueError as enc_err: logging.error(f"Logging failed: {enc_err}")
                 logging.info(log_entry)
            else:
                 flash(f"Seed '{seed_to_reactivate}' not found or could not be removed.", "warning")
        else:
            flash("Incorrect Reactivation Password.", "error")
            logging.warning(f"Failed reactivation attempt for seed '{seed_to_reactivate}' from IP {request.remote_addr} - incorrect password.")

    except ValueError:
        logging.error("Seed reactivation check failed: Invalid hash format stored.")
        flash("Reactivation configuration error.", "error")
    except Exception as e:
        logging.error(f"Error during seed reactivation DB operation for '{seed_to_reactivate}': {e}")
        flash(f"An error occurred during reactivation: {e}", "error")

    return redirect(url_for('secret_admin_route'))


@app.route('/confirm-panic', methods=['GET', 'POST'])
def confirm_panic():
    referrer = request.referrer
    is_from_index = referrer and referrer.endswith(url_for('index'))

    if request.method == 'GET' and not is_from_index:
        flash("Panic action must be initiated from the main page.", "warning")
        return redirect(url_for('index'))

    if request.method == 'POST':
        password_attempt = request.form.get('password')
        ip_address = request.remote_addr

        try:
            if bcrypt.checkpw(password_attempt.encode('utf-8'), REACTIVATION_PASSWORD_HASH.encode('utf-8')):
                logging.warning(f"PANIC ACTION CONFIRMED by IP: {ip_address}. Initiating cleanup, setting flag, and restarting.")
                seeds_cleared = clear_all_seeds_db()
                logs_cleared = clear_log_file(LOG_FILE)

                if seeds_cleared and logs_cleared:
                    log_entry = f"IP: {ip_address} - PANIC ACTION successful: Seeds and logs cleared. Setting flag and restarting..."
                    logging.warning(log_entry)
                    try:
                        enc_log = encrypt_data(encryption_key, log_entry)
                        append_encrypted_log(LOG_FILE, enc_log)
                    except ValueError as enc_err: logging.error(f"Logging panic result failed: {enc_err}")

                    # --- CREATE PANIC FLAG FILE ---
                    try:
                        with open(PANIC_FLAG_FILE, 'w') as f:
                            f.write(f"Panic activated at {time.time()} by {ip_address}")
                        logging.info(f"Panic flag file '{PANIC_FLAG_FILE}' created.")
                    except Exception as flag_err:
                        logging.error(f"CRITICAL: Failed to create panic flag file '{PANIC_FLAG_FILE}': {flag_err}. Restarting anyway.")

                    # --- INITIATE RESTART ---
                    restart_application() # This function attempts os.execv
                    # If restart fails, the code below might run
                    return "PANIC ACTION EXECUTED, BUT RESTART FAILED. Please restart the server manually.", 500

                else:
                    flash("PANIC ACTION PARTIALLY FAILED: Check logs for details. Flag NOT set, Restart NOT initiated.", "danger")
                    log_entry = f"IP: {ip_address} - PANIC ACTION FAILED or partially failed. Flag NOT set, Restart aborted."
                    logging.error(log_entry)
                    try:
                        enc_log = encrypt_data(encryption_key, log_entry)
                        append_encrypted_log(LOG_FILE, enc_log)
                    except ValueError as enc_err: logging.error(f"Logging panic failure failed: {enc_err}")
                    return render_template('confirm_panic.html')

            else:
                flash("Incorrect Confirmation Password. Panic action aborted.", "error")
                logging.warning(f"Failed PANIC confirmation from IP: {ip_address} - incorrect password.")
                return render_template('confirm_panic.html')

        except ValueError:
            logging.error("Panic confirmation check failed: Invalid hash format stored.")
            flash("Panic confirmation configuration error.", "error")
            return render_template('confirm_panic.html')
        except Exception as e:
            logging.error(f"Error during panic action execution: {e}")
            flash(f"An error occurred during panic action: {e}", "error")
            return render_template('confirm_panic.html')

    # GET request
    return render_template('confirm_panic.html')

# --- NEW Reset Panic Route ---
@app.route('/reset-panic', methods=['GET', 'POST'])
def reset_panic():
    # This route is allowed even in panic mode by before_request handler

    # Require admin login to access reset page/action
    if not session.get('logged_in'):
        flash("Admin login required to reset panic mode.", "warning")
        # Redirect to login, which should work even in panic if coming from here
        return redirect(url_for('login'))

    if request.method == 'POST':
        password_attempt = request.form.get('password')
        ip_address = request.remote_addr

        try:
            # Use ADMIN password for reset confirmation
            if bcrypt.checkpw(password_attempt.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8')):
                logging.warning(f"PANIC RESET INITIATED by Admin (IP: {ip_address}). Removing flag and restarting.")

                # --- REMOVE PANIC FLAG FILE ---
                flag_removed = False
                try:
                    if os.path.exists(PANIC_FLAG_FILE):
                        os.remove(PANIC_FLAG_FILE)
                        logging.info(f"Panic flag file '{PANIC_FLAG_FILE}' removed.")
                        flag_removed = True
                    else:
                        logging.warning(f"Panic flag file '{PANIC_FLAG_FILE}' not found during reset.")
                        flag_removed = True # Consider it success if flag wasn't there
                except Exception as flag_err:
                    logging.error(f"CRITICAL: Failed to remove panic flag file '{PANIC_FLAG_FILE}': {flag_err}. Restarting anyway.")
                    # Proceed with restart even if flag removal failed

                log_entry = f"IP: {ip_address} - Admin reset PANIC MODE. Flag removed: {flag_removed}. Restarting application..."
                logging.warning(log_entry)
                try:
                    enc_log = encrypt_data(encryption_key, log_entry)
                    append_encrypted_log(LOG_FILE, enc_log)
                except ValueError as enc_err: logging.error(f"Logging panic reset failed: {enc_err}")

                # --- INITIATE RESTART ---
                restart_application()
                return "PANIC RESET EXECUTED, BUT RESTART FAILED. Please restart the server manually.", 500

            else:
                flash("Incorrect Admin Password. Panic reset aborted.", "error")
                logging.warning(f"Failed PANIC RESET confirmation from IP: {ip_address} - incorrect admin password.")
                return render_template('reset_panic.html') # Show form again

        except ValueError:
            logging.error("Panic reset check failed: Invalid hash format stored.")
            flash("Panic reset configuration error.", "error")
            return render_template('reset_panic.html')
        except Exception as e:
            logging.error(f"Error during panic reset execution: {e}")
            flash(f"An error occurred during panic reset: {e}", "error")
            return render_template('reset_panic.html')

    # GET request
    return render_template('reset_panic.html')


@app.route('/logout')
def legOut():
    # ... (existing logout logic with IP logging) ...
    ip_address = request.remote_addr
    session.pop('logged_in', None)
    flash("You have been logged out.", "info")
    logging.info(f"Admin logged out from IP: {ip_address}") # Log IP on logout
    return render_template('panic.html')


if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
        print("Created 'templates' directory. Make sure HTML files are inside.")

    if PANIC_MODE_ACTIVE:
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! WARNING: Application starting in PANIC MODE. !!!")
        print(f"!!! Flag file '{PANIC_FLAG_FILE}' detected.      !!!")
        print("!!! Most routes will be blocked.                 !!!")
        print("!!! Use the reset trigger/route to recover.      !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    elif not encryption_key:
         print("\nCRITICAL WARNING: Encryption key could not be loaded.")
         # ... (rest of warning) ...

    print("Flask app running. Access at http://127.0.0.1:5000/")
    app.run(debug=True, use_reloader=False, port=5555) # use_reloader=False recommended with os.execv
