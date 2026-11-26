from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import os
import sys
import platform
import time
import datetime
import json
from functools import wraps
from importlib.metadata import version as pkg_version, PackageNotFoundError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'change-me-to-a-random-secret'

DB_NAME = 'users.db'
START_TIME = time.time()

# ==========================================================
#  РОЛИ
# ==========================================================
ALL_ROLES = ('user', 'moderator', 'admin', 'super_admin', 'dashboard', 'inventory', 'faq_editor')
ADMIN_ROLES = ('admin', 'super_admin')
TO_ROLES = ('dashboard',) + ADMIN_ROLES

PINNED_POSITIONS = [
    'Моторное масло', 'Салонный фильтр', 'Клапана', 'Газовый фильтр',
    'Воздушный фильтр', 'Свечи зажигания', 'Масло в коробке', 'АКБ',
]


# ==========================================================
#  БАЗА ДАННЫХ
# ==========================================================

def init_db():
    conn = sqlite3.connect(DB_NAME)

    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    UNIQUE NOT NULL,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'user',
            created_at TEXT    NOT NULL DEFAULT '',
            last_login TEXT    NOT NULL DEFAULT ''
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS maintenance (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            date     TEXT NOT NULL,
            name     TEXT NOT NULL,
            data     TEXT NOT NULL DEFAULT ''
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS maintenance_archive (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            orig_id     INTEGER,
            date        TEXT NOT NULL,
            name        TEXT NOT NULL,
            data        TEXT NOT NULL DEFAULT '',
            deleted_by  TEXT NOT NULL DEFAULT '',
            deleted_at  TEXT NOT NULL DEFAULT ''
        )
    ''')

    # audit_log теперь содержит undo_kind и undo_data
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL,
            username   TEXT NOT NULL,
            action     TEXT NOT NULL,
            details    TEXT NOT NULL DEFAULT '',
            undo_kind  TEXT NOT NULL DEFAULT '',
            undo_data  TEXT NOT NULL DEFAULT ''
        )
    ''')

    # миграция старой audit_log
    existing = [row[1] for row in conn.execute('PRAGMA table_info(audit_log)')]
    if 'undo_kind' not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN undo_kind TEXT NOT NULL DEFAULT ''")
    if 'undo_data' not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN undo_data TEXT NOT NULL DEFAULT ''")

    conn.execute('''
        CREATE TABLE IF NOT EXISTS dashboard_columns (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT UNIQUE NOT NULL,
            pinned     INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ''
        )
    ''')

    # fields — JSON-список объектов {name, options}
    conn.execute('''
        CREATE TABLE IF NOT EXISTS inventory_categories (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            name   TEXT UNIQUE NOT NULL,
            fields TEXT NOT NULL DEFAULT '[]'
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS inventory_items (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            data        TEXT NOT NULL DEFAULT '{}',
            created_at  TEXT NOT NULL DEFAULT ''
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS faq (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            question   TEXT NOT NULL,
            answer     TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
    ''')

    for name in PINNED_POSITIONS:
        conn.execute(
            'INSERT OR IGNORE INTO dashboard_columns (name, pinned, created_by, created_at) '
            'VALUES (?, 1, "system", ?)',
            (name, now_str())
        )

    conn.commit()
    conn.close()


def now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def log_action(username, action, details='', undo_kind='', undo_data=None):
    """
    Пишет запись в audit_log.
    undo_kind — тип отката (см. admin_undo), пустая строка = откат невозможен.
    undo_data — словарь с данными для отката (сериализуется в JSON).
    """
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        'INSERT INTO audit_log (ts, username, action, details, undo_kind, undo_data) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (now_str(), username, action, details,
         undo_kind,
         json.dumps(undo_data, ensure_ascii=False) if undo_data else '')
    )
    conn.commit()
    conn.close()


def get_audit_log(limit=200):
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, ts, username, action, details, undo_kind, undo_data '
        'FROM audit_log ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return rows


# ---------- USERS ----------

def find_user(username):
    conn = sqlite3.connect(DB_NAME)
    user = conn.execute(
        'SELECT id, username, password, role, created_at, last_login '
        'FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    return user


def create_user(username, password, role='user'):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
            (username, generate_password_hash(password), role, now_str())
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    users = conn.execute(
        'SELECT id, username, role, created_at, last_login FROM users ORDER BY id'
    ).fetchall()
    conn.close()
    return users


def delete_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def update_last_login(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (now_str(), user_id))
    conn.commit()
    conn.close()


def set_user_roles(user_id, roles_str):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (roles_str, user_id))
    conn.commit()
    conn.close()


# ---------- MAINTENANCE ----------

def add_maintenance(date, name, data):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.execute(
        'INSERT INTO maintenance (date, name, data) VALUES (?, ?, ?)',
        (date, name, data)
    )
    new_id = cur.lastrowid
    conn.execute(
        'INSERT OR IGNORE INTO dashboard_columns (name, pinned, created_by, created_at) '
        'VALUES (?, 0, "auto", ?)',
        (name, now_str())
    )
    conn.commit()
    conn.close()
    return new_id


def delete_maintenance(record_id, username):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT date, name, data FROM maintenance WHERE id = ?', (record_id,)
    ).fetchone()
    if row:
        conn.execute(
            'INSERT INTO maintenance_archive '
            '(orig_id, date, name, data, deleted_by, deleted_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (record_id, row[0], row[1], row[2], username, now_str())
        )
        conn.execute('DELETE FROM maintenance WHERE id = ?', (record_id,))
    conn.commit()
    conn.close()
    return row


def get_archive():
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, orig_id, date, name, data, deleted_by, deleted_at '
        'FROM maintenance_archive ORDER BY id DESC'
    ).fetchall()
    conn.close()
    return rows


def restore_from_archive(archive_id, username):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT orig_id, date, name, data FROM maintenance_archive WHERE id = ?',
        (archive_id,)
    ).fetchone()
    if not row:
        conn.close()
        return False
    _, date, name, data = row
    conn.execute(
        'INSERT INTO maintenance (date, name, data) VALUES (?, ?, ?)',
        (date, name, data)
    )
    conn.execute(
        'INSERT OR IGNORE INTO dashboard_columns (name, pinned, created_by, created_at) '
        'VALUES (?, 0, "auto", ?)',
        (name, now_str())
    )
    conn.execute('DELETE FROM maintenance_archive WHERE id = ?', (archive_id,))
    conn.commit()
    conn.close()
    return True


def get_all_maintenance():
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, date, name, data FROM maintenance ORDER BY date DESC, id DESC'
    ).fetchall()
    conn.close()
    return rows


# ---------- DASHBOARD COLUMNS ----------

def add_column(name, username):
    name = name.strip()
    if not name:
        return False, 'Пустое название'
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO dashboard_columns (name, pinned, created_by, created_at) '
            'VALUES (?, 0, ?, ?)',
            (name, username, now_str())
        )
        conn.commit()
        conn.close()
        return True, ''
    except sqlite3.IntegrityError:
        return False, 'Такая колонка уже есть'


def delete_column(col_id):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT name, pinned FROM dashboard_columns WHERE id = ?', (col_id,)
    ).fetchone()
    if not row:
        conn.close()
        return False, 'Колонка не найдена', None
    name, pinned = row
    if pinned:
        conn.close()
        return False, 'Забинженную колонку удалить нельзя', None
    conn.execute('DELETE FROM dashboard_columns WHERE id = ?', (col_id,))
    conn.commit()
    conn.close()
    return True, '', {'name': name, 'pinned': pinned}


def restore_column(name, pinned=0, created_by='system'):
    """Восстанавливает колонку (для отката)."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO dashboard_columns (name, pinned, created_by, created_at) '
            'VALUES (?, ?, ?, ?)',
            (name, pinned, created_by, now_str())
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_dashboard():
    conn = sqlite3.connect(DB_NAME)
    cols = conn.execute(
        'SELECT id, name, pinned, created_by, created_at '
        'FROM dashboard_columns ORDER BY pinned DESC, id'
    ).fetchall()

    dashboard = []
    for col in cols:
        row = conn.execute(
            'SELECT date, data FROM maintenance WHERE name = ? '
            'ORDER BY date DESC, id DESC LIMIT 1', (col[1],)
        ).fetchone()
        dashboard.append({
            'id': col[0],
            'name': col[1],
            'pinned': bool(col[2]),
            'created_by': col[3],
            'created_at': col[4],
            'data': row[1] if row and row[1] else '—',
            'date': row[0] if row else '—',
        })
    conn.close()
    return dashboard


# ---------- BULK IMPORT ----------

def parse_date_any(s):
    s = s.strip().strip('"').strip("'")
    for fmt in ('%d.%m.%Y', '%d,%m,%Y', '%Y-%m-%d', '%d/%m/%Y'):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return dt.strftime('%Y-%m-%d')
        except ValueError:
            continue
    return None


def parse_bulk_text(text):
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    rows = []
    errors = []

    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in '\n\t ':
            i += 1
        if i >= n:
            break

        fields = []
        for _ in range(3):
            if i >= n:
                break
            while i < n and text[i] in ' \t':
                i += 1
            if i < n and text[i] == '"':
                i += 1
                buf = []
                while i < n:
                    if text[i] == '"':
                        if i + 1 < n and text[i + 1] == '"':
                            buf.append('"')
                            i += 2
                        else:
                            i += 1
                            break
                    else:
                        buf.append(text[i])
                        i += 1
                fields.append(''.join(buf))
            else:
                buf = []
                while i < n and text[i] not in '\t\n':
                    buf.append(text[i])
                    i += 1
                fields.append(''.join(buf).strip())

            if i < n and text[i] == '\t':
                i += 1

        if len(fields) >= 3:
            date_raw, name, data = fields[0], fields[1], fields[2]
            if not date_raw.strip() or date_raw.strip().lower() == 'дата':
                continue
            iso = parse_date_any(date_raw)
            if not iso:
                errors.append(f'Плохая дата: "{date_raw}"')
                continue
            if not name.strip():
                errors.append(f'Пустое название в строке {date_raw}')
                continue
            rows.append((iso, name.strip(), data.strip()))
        elif any(f.strip() for f in fields):
            errors.append(f'Неполная строка: {fields}')

    return rows, errors


# ---------- INVENTORY ----------

def get_categories():
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, name, fields FROM inventory_categories ORDER BY name'
    ).fetchall()
    conn.close()
    return rows


def add_category(name, fields_list):
    """fields_list — список объектов {name, options}."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO inventory_categories (name, fields) VALUES (?, ?)',
            (name, json.dumps(fields_list, ensure_ascii=False))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def delete_category(cat_id):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT name, fields FROM inventory_categories WHERE id = ?', (cat_id,)
    ).fetchone()
    if not row:
        conn.close()
        return None
    # удаляем записи и категорию
    conn.execute('DELETE FROM inventory_items WHERE category_id = ?', (cat_id,))
    conn.execute('DELETE FROM inventory_categories WHERE id = ?', (cat_id,))
    conn.commit()
    conn.close()
    return {'name': row[0], 'fields': json.loads(row[1])}


def restore_category(name, fields):
    """Для отката: восстанавливает категорию (без элементов)."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO inventory_categories (name, fields) VALUES (?, ?)',
            (name, json.dumps(fields, ensure_ascii=False))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_items(category_id):
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, data, created_at FROM inventory_items '
        'WHERE category_id = ? ORDER BY id', (category_id,)
    ).fetchall()
    conn.close()
    return rows


def add_item(category_id, data_dict):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.execute(
        'INSERT INTO inventory_items (category_id, data, created_at) VALUES (?, ?, ?)',
        (category_id, json.dumps(data_dict, ensure_ascii=False), now_str())
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def delete_item(item_id):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT category_id, data, created_at FROM inventory_items WHERE id = ?',
        (item_id,)
    ).fetchone()
    if not row:
        conn.close()
        return None
    conn.execute('DELETE FROM inventory_items WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    return {'category_id': row[0], 'data': json.loads(row[1]), 'created_at': row[2]}


def restore_item(category_id, data_dict):
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        'INSERT INTO inventory_items (category_id, data, created_at) VALUES (?, ?, ?)',
        (category_id, json.dumps(data_dict, ensure_ascii=False), now_str())
    )
    conn.commit()
    conn.close()


# ---------- FAQ ----------

def get_faq():
    conn = sqlite3.connect(DB_NAME)
    rows = conn.execute(
        'SELECT id, question, answer, created_by, created_at, updated_at '
        'FROM faq ORDER BY id'
    ).fetchall()
    conn.close()
    return rows


def add_faq(question, answer, username):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.execute(
        'INSERT INTO faq (question, answer, created_by, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (question, answer, username, now_str(), now_str())
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def update_faq(faq_id, question, answer):
    conn = sqlite3.connect(DB_NAME)
    old = conn.execute(
        'SELECT question, answer FROM faq WHERE id = ?', (faq_id,)
    ).fetchone()
    conn.execute(
        'UPDATE faq SET question = ?, answer = ?, updated_at = ? WHERE id = ?',
        (question, answer, now_str(), faq_id)
    )
    conn.commit()
    conn.close()
    return old


def delete_faq(faq_id):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT question, answer, created_by, created_at FROM faq WHERE id = ?',
        (faq_id,)
    ).fetchone()
    if not row:
        conn.close()
        return None
    conn.execute('DELETE FROM faq WHERE id = ?', (faq_id,))
    conn.commit()
    conn.close()
    return {'question': row[0], 'answer': row[1],
            'created_by': row[2], 'created_at': row[3]}


def restore_faq(question, answer, created_by):
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        'INSERT INTO faq (question, answer, created_by, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (question, answer, created_by, now_str(), now_str())
    )
    conn.commit()
    conn.close()


# ==========================================================
#  СЕРВЕРНАЯ ИНФОРМАЦИЯ
# ==========================================================

def flask_version():
    try:
        return pkg_version('flask')
    except PackageNotFoundError:
        return 'unknown'


def get_server_info():
    uptime_seconds = int(time.time() - START_TIME)
    hours, rem   = divmod(uptime_seconds, 3600)
    minutes, sec = divmod(rem, 60)

    db_size = os.path.getsize(DB_NAME) if os.path.exists(DB_NAME) else 0

    conn = sqlite3.connect(DB_NAME)
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_ma    = conn.execute('SELECT COUNT(*) FROM maintenance').fetchone()[0]
    total_arch  = conn.execute('SELECT COUNT(*) FROM maintenance_archive').fetchone()[0]
    total_items = conn.execute('SELECT COUNT(*) FROM inventory_items').fetchone()[0]
    total_faq   = conn.execute('SELECT COUNT(*) FROM faq').fetchone()[0]
    total_cols  = conn.execute('SELECT COUNT(*) FROM dashboard_columns').fetchone()[0]
    conn.close()

    return {
        'os':            f'{platform.system()} {platform.release()}',
        'python':        sys.version.split()[0],
        'flask':         flask_version(),
        'hostname':      platform.node(),
        'uptime':        f'{hours} ч {minutes} мин {sec} сек',
        'db_size':       f'{db_size} байт' if db_size < 1024 else f'{db_size / 1024:.1f} КБ',
        'total_users':   total_users,
        'total_records': total_ma,
        'total_archive': total_arch,
        'total_items':   total_items,
        'total_faq':     total_faq,
        'total_cols':    total_cols,
        'server_time':   now_str(),
    }


# ==========================================================
#  РОЛИ И ДЕКОРАТОРЫ
# ==========================================================

def parse_roles(role_str):
    if not role_str:
        return []
    return [r.strip() for r in role_str.split(',') if r.strip()]


def has_any_role(user_roles, roles):
    return any(r in user_roles for r in roles)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not has_any_role(session.get('roles', []), ADMIN_ROLES):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


def super_admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'super_admin' not in session.get('roles', []):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


def to_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not has_any_role(session.get('roles', []), TO_ROLES):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


def inventory_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not has_any_role(session.get('roles', []), ('inventory',) + ADMIN_ROLES):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


def faq_editor_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not has_any_role(session.get('roles', []), ('faq_editor',) + ADMIN_ROLES):
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


# ==========================================================
#  МАРШРУТЫ: БАЗОВЫЕ
# ==========================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    user = find_user(username)
    if user and check_password_hash(user[2], password):
        roles = parse_roles(user[3])
        session['user_id']  = user[0]
        session['username'] = user[1]
        session['roles']    = roles
        update_last_login(user[0])
        log_action(user[1], 'login', f'роли: {",".join(roles)}')

        if has_any_role(roles, ADMIN_ROLES):
            return redirect(url_for('admin'))
        if 'dashboard' in roles:
            return redirect(url_for('to_page'))
        if 'inventory' in roles:
            return redirect(url_for('inventory'))
        if 'faq_editor' in roles:
            return redirect(url_for('faq_page'))

        return render_template('index.html', success=f'Добро пожаловать, {username}!')
    return render_template('index.html', error='Неверный логин или пароль')


@app.route('/logout')
def logout():
    if session.get('username'):
        log_action(session['username'], 'logout')
    session.clear()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm', '')

    if not username or not password:
        return render_template('register.html', error='Заполните все поля')
    if len(password) < 5:
        return render_template('register.html', error='Пароль должен быть не короче 5 символов')
    if password != confirm:
        return render_template('register.html', error='Пароли не совпадают')

    if create_user(username, password, role='user'):
        log_action(username, 'register', 'создан аккаунт')
        return redirect(url_for('index', registered='1'))
    return render_template('register.html', error='Такой логин уже занят')


# ==========================================================
#  УПРАВЛЕНИЕ ТО
# ==========================================================

@app.route('/to')
@to_required
def to_page():
    return render_template(
        'to.html',
        dashboard=get_dashboard(),
        maintenance=get_all_maintenance(),
        archive=get_archive(),
    )


@app.route('/to/api')
@to_required
def to_api():
    return jsonify({
        'dashboard':   get_dashboard(),
        'maintenance': get_all_maintenance(),
        'server_time': now_str(),
    })


@app.route('/to/column/add', methods=['POST'])
@to_required
def to_add_column():
    name = request.form.get('name', '')
    ok, msg = add_column(name, session['username'])
    if ok:
        log_action(session['username'], 'to.column.add', name,
                   undo_kind='delete_column', undo_data={'name': name})
        return redirect(url_for('to_page', ok='1'))
    return redirect(url_for('to_page', error=msg))


@app.route('/to/column/delete/<int:col_id>', methods=['POST'])
@to_required
def to_delete_column(col_id):
    ok, msg, data = delete_column(col_id)
    if ok:
        log_action(session['username'], 'to.column.delete', f'id={col_id}',
                   undo_kind='restore_column', undo_data=data)
        return redirect(url_for('to_page', ok='1'))
    return redirect(url_for('to_page', error=msg))


@app.route('/to/maintenance/add', methods=['POST'])
@to_required
def to_add_maintenance():
    date = request.form.get('date', '').strip()
    name = request.form.get('name', '').strip()
    data = request.form.get('data', '').strip()
    if not date or not name:
        return redirect(url_for('to_page', error='Укажите дату и название'))
    try:
        datetime.datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return redirect(url_for('to_page', error='Неверный формат даты'))

    new_id = add_maintenance(date, name, data)
    log_action(session['username'], 'to.maintenance.add',
               f'{date} | {name} | {data[:40]}',
               undo_kind='delete_maintenance', undo_data={'id': new_id})
    return redirect(url_for('to_page', ok='1'))


@app.route('/to/maintenance/delete/<int:record_id>', methods=['POST'])
@to_required
def to_delete_maintenance(record_id):
    row = delete_maintenance(record_id, session['username'])
    if row:
        log_action(session['username'], 'to.maintenance.delete', f'id={record_id}',
                   undo_kind='restore_maintenance',
                   undo_data={'date': row[0], 'name': row[1], 'data': row[2]})
        return redirect(url_for('to_page', ok='1'))
    return redirect(url_for('to_page', error='Запись не найдена'))


@app.route('/to/maintenance/import', methods=['POST'])
@to_required
def to_import_maintenance():
    text = request.form.get('bulk_text', '')
    if not text.strip():
        return redirect(url_for('to_page', error='Вставьте текст для импорта'))

    rows, errors = parse_bulk_text(text)
    added = 0
    for date, name, data in rows:
        add_maintenance(date, name, data)
        added += 1

    log_action(session['username'], 'to.maintenance.import',
               f'добавлено: {added}, ошибок: {len(errors)}')

    if errors:
        msg = f'Импортировано {added}. Ошибок: {len(errors)}. ' + '; '.join(errors[:5])
        return redirect(url_for('to_page', error=msg))
    return redirect(url_for('to_page', ok=f'импортировано {added}'))


@app.route('/to/restore/<int:archive_id>', methods=['POST'])
@to_required
def to_restore(archive_id):
    if restore_from_archive(archive_id, session['username']):
        log_action(session['username'], 'to.maintenance.restore', f'archive_id={archive_id}')
        return redirect(url_for('to_page', ok='1'))
    return redirect(url_for('to_page', error='Запись не найдена в корзине'))


# ==========================================================
#  ИНВЕНТАРЬ
# ==========================================================

@app.route('/inventory')
@inventory_required
def inventory():
    cats = []
    for cat in get_categories():
        items = get_items(cat[0])
        cats.append({
            'id': cat[0],
            'name': cat[1],
            'fields': json.loads(cat[2]),
            'rows': [
                {'id': it[0], 'data': json.loads(it[1]), 'created_at': it[2]}
                for it in items
            ],
        })
    return render_template(
        'inventory.html',
        categories=cats,
        can_edit=has_any_role(session.get('roles', []), ADMIN_ROLES),
    )


@app.route('/inventory/category/add', methods=['POST'])
@admin_required
def inventory_add_category():
    name = request.form.get('name', '').strip()
    fields_raw = request.form.get('fields', '').strip()

    if not name:
        return redirect(url_for('inventory', error='Укажите название категории'))

    fields = []
    for line in fields_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # формат: "Название | опция1, опция2, опция3"
        if '|' in line:
            fname, opts = line.split('|', 1)
            fname = fname.strip()
            options = [o.strip() for o in opts.split(',') if o.strip()]
            fields.append({'name': fname, 'options': options})
        else:
            fields.append({'name': line, 'options': []})

    if not fields:
        return redirect(url_for('inventory', error='Добавьте хотя бы одно поле'))

    if not add_category(name, fields):
        return redirect(url_for('inventory', error='Такая категория уже есть'))

    log_action(session['username'], 'inventory.category.add',
               f'{name} [{", ".join(f["name"] for f in fields)}]',
               undo_kind='delete_category', undo_data={'name': name})
    return redirect(url_for('inventory', ok='1'))


@app.route('/inventory/category/delete/<int:cat_id>', methods=['POST'])
@admin_required
def inventory_delete_category(cat_id):
    data = delete_category(cat_id)
    if data:
        log_action(session['username'], 'inventory.category.delete',
                   f'id={cat_id} ({data["name"]})',
                   undo_kind='restore_category', undo_data=data)
    return redirect(url_for('inventory', ok='1'))


@app.route('/inventory/item/add/<int:cat_id>', methods=['POST'])
@inventory_required
def inventory_add_item(cat_id):
    cat = next((c for c in get_categories() if c[0] == cat_id), None)
    if not cat:
        return redirect(url_for('inventory', error='Категория не найдена'))

    fields = json.loads(cat[2])
    data = {f['name']: request.form.get(f'f_{i}', '') for i, f in enumerate(fields)}
    new_id = add_item(cat_id, data)

    log_action(session['username'], 'inventory.item.add',
               f'{cat[1]}: {data}',
               undo_kind='delete_item', undo_data={'id': new_id})
    return redirect(url_for('inventory', ok='1'))


@app.route('/inventory/item/delete/<int:item_id>', methods=['POST'])
@inventory_required
def inventory_delete_item(item_id):
    data = delete_item(item_id)
    if data:
        log_action(session['username'], 'inventory.item.delete',
                   f'id={item_id}',
                   undo_kind='restore_item', undo_data=data)
    return redirect(url_for('inventory', ok='1'))


# ==========================================================
#  FAQ
# ==========================================================

@app.route('/faq')
@login_required
def faq_page():
    return render_template(
        'faq.html',
        faq=get_faq(),
        can_edit=has_any_role(session.get('roles', []), ('faq_editor',) + ADMIN_ROLES),
    )


@app.route('/faq/add', methods=['POST'])
@faq_editor_required
def faq_add():
    q = request.form.get('question', '').strip()
    a = request.form.get('answer', '').strip()
    if not q or not a:
        return redirect(url_for('faq_page', error='Заполните вопрос и ответ'))
    new_id = add_faq(q, a, session['username'])
    log_action(session['username'], 'faq.add', q[:60],
               undo_kind='delete_faq', undo_data={'id': new_id})
    return redirect(url_for('faq_page', ok='1'))


@app.route('/faq/update/<int:faq_id>', methods=['POST'])
@faq_editor_required
def faq_update(faq_id):
    q = request.form.get('question', '').strip()
    a = request.form.get('answer', '').strip()
    old = update_faq(faq_id, q, a)
    if old:
        log_action(session['username'], 'faq.update', f'id={faq_id}',
                   undo_kind='update_faq',
                   undo_data={'id': faq_id, 'question': old[0], 'answer': old[1]})
    return redirect(url_for('faq_page', ok='1'))


@app.route('/faq/delete/<int:faq_id>', methods=['POST'])
@faq_editor_required
def faq_delete(faq_id):
    data = delete_faq(faq_id)
    if data:
        log_action(session['username'], 'faq.delete', f'id={faq_id}',
                   undo_kind='restore_faq', undo_data=data)
    return redirect(url_for('faq_page', ok='1'))


# ==========================================================
#  АДМИН-ПАНЕЛЬ
# ==========================================================

@app.route('/admin')
@admin_required
def admin():
    return render_template(
        'admin.html',
        info=get_server_info(),
        users=get_all_users(),
        audit=get_audit_log(200),
        all_roles=ALL_ROLES,
        can_undo='super_admin' in session.get('roles', []),
    )


@app.route('/admin/api/data')
@admin_required
def admin_api_data():
    return jsonify({
        'info':        get_server_info(),
        'server_time': now_str(),
    })


@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return redirect(url_for('admin', error='Нельзя удалить себя'))

    target = next((u for u in get_all_users() if u[0] == user_id), None)
    if not target:
        return redirect(url_for('admin', error='Пользователь не найден'))

    if has_any_role(parse_roles(target[2]), ADMIN_ROLES) and 'super_admin' not in session.get('roles', []):
        return redirect(url_for('admin', error='Только главный админ может удалять админов'))

    delete_user(user_id)
    log_action(session['username'], 'user.delete', target[1])
    return redirect(url_for('admin', deleted='1'))


@app.route('/admin/roles/<int:user_id>', methods=['POST'])
@admin_required
def admin_set_roles(user_id):
    if user_id == session.get('user_id'):
        return redirect(url_for('admin', error='Нельзя менять свои роли'))

    new_roles = request.form.getlist('roles')
    for r in new_roles:
        if r not in ALL_ROLES:
            return redirect(url_for('admin', error=f'Неизвестная роль: {r}'))
    if not new_roles:
        return redirect(url_for('admin', error='Нужна хотя бы одна роль'))

    is_super = 'super_admin' in session.get('roles', [])
    if 'super_admin' in new_roles and not is_super:
        return redirect(url_for('admin', error='Только главный админ может назначать главного админа'))

    if not is_super:
        target = next((u for u in get_all_users() if u[0] == user_id), None)
        if target and has_any_role(parse_roles(target[2]), ADMIN_ROLES):
            return redirect(url_for('admin', error='Только главный админ может менять админов'))

    old = next((u for u in get_all_users() if u[0] == user_id), None)
    set_user_roles(user_id, ','.join(new_roles))

    undo_data = {'user_id': user_id, 'old_roles': old[2] if old else ''}
    log_action(session['username'], 'user.roles',
               f'user_id={user_id} → {",".join(new_roles)}',
               undo_kind='restore_user_roles', undo_data=undo_data)
    return redirect(url_for('admin', roles_changed='1'))


# ==========================================================
#  УНИВЕРСАЛЬНЫЙ ОТКАТ
# ==========================================================

@app.route('/admin/undo/<int:log_id>', methods=['POST'])
@super_admin_required
def admin_undo(log_id):
    """Откатывает действие по записи в audit_log."""
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        'SELECT ts, username, action, details, undo_kind, undo_data '
        'FROM audit_log WHERE id = ?', (log_id,)
    ).fetchone()
    conn.close()

    if not row:
        return redirect(url_for('admin', error='Запись лога не найдена'))

    _, log_user, action, details, kind, undo_json = row
    if not kind or not undo_json:
        return redirect(url_for('admin', error='Это действие нельзя откатить'))

    try:
        data = json.loads(undo_json)
    except json.JSONDecodeError:
        return redirect(url_for('admin', error='Повреждённые данные отката'))

    ok = False
    message = ''

    if kind == 'delete_column':
        ok = restore_column(data['name'], 0, session['username'])

    elif kind == 'restore_column':
        ok = restore_column(data['name'], data.get('pinned', 0),
                            data.get('created_by', 'system'))

    elif kind == 'delete_maintenance':
        # отменяем добавление — удаляем запись в корзину
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'INSERT INTO maintenance_archive '
            '(orig_id, date, name, data, deleted_by, deleted_at) '
            'VALUES (?, "", "undo", "отмена добавления", ?, ?)',
            (data['id'], session['username'], now_str())
        )
        conn.execute('DELETE FROM maintenance WHERE id = ?', (data['id'],))
        conn.commit()
        conn.close()
        ok = True

    elif kind == 'restore_maintenance':
        # отменяем удаление — возвращаем в maintenance
        add_maintenance(data['date'], data['name'], data['data'])
        ok = True

    elif kind == 'delete_category':
        # отменяем добавление категории — удаляем её
        conn = sqlite3.connect(DB_NAME)
        conn.execute('DELETE FROM inventory_categories WHERE name = ?', (data['name'],))
        conn.commit()
        conn.close()
        ok = True

    elif kind == 'restore_category':
        ok = restore_category(data['name'], data['fields'])

    elif kind == 'delete_item':
        conn = sqlite3.connect(DB_NAME)
        conn.execute('DELETE FROM inventory_items WHERE id = ?', (data['id'],))
        conn.commit()
        conn.close()
        ok = True

    elif kind == 'restore_item':
        restore_item(data['category_id'], data['data'])
        ok = True

    elif kind == 'delete_faq':
        conn = sqlite3.connect(DB_NAME)
        conn.execute('DELETE FROM faq WHERE id = ?', (data['id'],))
        conn.commit()
        conn.close()
        ok = True

    elif kind == 'update_faq':
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            'UPDATE faq SET question = ?, answer = ?, updated_at = ? WHERE id = ?',
            (data['question'], data['answer'], now_str(), data['id'])
        )
        conn.commit()
        conn.close()
        ok = True

    elif kind == 'restore_faq':
        restore_faq(data['question'], data['answer'], data['created_by'])
        ok = True

    elif kind == 'restore_user_roles':
        set_user_roles(data['user_id'], data['old_roles'])
        ok = True

    else:
        return redirect(url_for('admin', error=f'Неизвестный тип отката: {kind}'))

    if not ok:
        return redirect(url_for('admin', error='Не удалось выполнить откат (возможно, конфликт данных)'))

    # Пишем в лог факт отката (без возможности откатить сам откат — чтобы не было рекурсии)
    log_action(session['username'], 'undo',
               f'log_id={log_id}, action={action}, by={log_user}')
    return redirect(url_for('admin', undo_ok='1'))


# ==========================================================
#  ЗАПУСК
# ==========================================================

if __name__ == '__main__':
    init_db()

    if not find_user('admin'):
        create_user('admin', 'admin123', role='super_admin')
        print('✅ Создан главный админ: логин "admin", пароль "admin123"')
    
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
