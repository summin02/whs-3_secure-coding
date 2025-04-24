import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import mysql.connector
from flask_socketio import SocketIO, emit
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_socketio import join_room


app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
socketio = SocketIO(app, manage_session=False)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# MySQL 연결 설정
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',  # 비밀번호 입력 필요
    database='used_market'
)
cursor = conn.cursor(dictionary=True)

#################### 함수 ####################


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           
    
def log_event(log_type, message):
    print(f"📤 로그 발생: [{log_type}] {message}")
    cursor.execute("INSERT INTO logs (log_type, message) VALUES (%s, %s)", (log_type, message))
    conn.commit()
    socketio.emit('new_log', {
        'log_type': log_type,
        'message': message
    }, namespace='/admin')
    
def log_item_action(user_id, item_id, action_type, description):
    """
    게시물 작업 로그를 기록하고 실시간으로 클라이언트에 전송
    """
    cursor.execute("""
        INSERT INTO item_logs (user_id, item_id, action_type, description)
        VALUES (%s, %s, %s, %s)
    """, (user_id, item_id, action_type, description))
    conn.commit()

    # 작업 완료 후 실시간 로그 전송 (여기서 게시물 작업 로그를 보내는 부분)
    socketio.emit('new_log', {
        'log_type': 'item',  # log_type이 'item'인 로그만 실시간으로 보내기
        'message': description,  # 메시지는 작업 설명
        'item_id': item_id,  # item_id도 포함
        'action_type': action_type  # 작업 종류 (예: create, delete)
    }, namespace='/admin')  # 네임스페이스를 /admin으로 전송
    
# 신고 로그를 기록하는 함수
def log_report(report_type, reporter_id, reported_user_id, reason, reported_item_title, item_id):
    print(f"🚨 신고 로그 발생: [{report_type}] 신고자: {reporter_id} → {reported_user_id}, 사유: {reason}, 신고된 게시물: {reported_item_title} (ID: {item_id})")
    
    # 해당 게시물 작성자 이름을 조회
    cursor.execute("""
        SELECT nickname 
        FROM users 
        WHERE id = %s
    """, (reported_user_id,))
    reported_user = cursor.fetchone()
    
    # 작성자 이름이 있으면 가져오고, 없으면 '알 수 없음'을 사용
    reported_user_name = reported_user['nickname'] if reported_user else '알 수 없음'
    
    cursor.execute("""
        INSERT INTO report_logs (reporter_id, reported_user_id, reason, reported_item_title, item_id, report_type, reported_item_user_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (reporter_id, reported_user_id, reason, reported_item_title, item_id, report_type, reported_user_id))
    conn.commit()

    # 실시간 신고 로그 발송
    socketio.emit('new_log', {
        'log_type': 'report',
        'reporter_name': reporter_id,  # 'reporter_name' 이라는 항목이 클라이언트에서 필요하다면 조정해주세요
        'reported_item_title': reported_item_title,
        'reported_item_id': item_id,
        'reported_user_name': reported_user_name,  # 게시물 작성자 이름을 전송
        'reason': reason,
        'timestamp': str(datetime.now())  # 현재 시간
    }, namespace='/admin')

#################### 관리자 페이지 ####################

@app.route('/')
def index():
    cursor.execute("SELECT * FROM items WHERE is_blocked = 0")
    items = cursor.fetchall()
    return render_template('index.html', items=items)

@app.route('/admin')
def admin_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect('/')

    # 관리자 페이지에서 'balance' 컬럼을 포함한 데이터 불러오기
    cursor.execute("SELECT id, email, nickname, balance, is_blocked, block_reason, is_admin FROM users")
    all_users = cursor.fetchall()

    admins = [u for u in all_users if u['is_admin']]
    users = [u for u in all_users if not u['is_admin']]

    return render_template('admin.html', admins=admins, users=users)


@app.route('/admin/promote/<int:user_id>', methods=['POST'])
def promote_to_admin(user_id):
    # 로그인 되어 있고 슈퍼관리자인 경우에만
    if not session.get('is_admin') or not session.get('is_superadmin'):
        return "권한 없음", 403

    cursor.execute("UPDATE users SET is_admin = TRUE WHERE id = %s", (user_id,))
    conn.commit()
    log_event('admin', f"슈퍼 관리자가 유저 ID {user_id} 에게 관리자 권한 부여")
    
    return redirect('/admin')

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
def demote_admin(user_id):
    if not session.get('is_superadmin'):
        return "접근 불가", 403
    cursor.execute("UPDATE users SET is_admin = 0 WHERE id = %s", (user_id,))
    conn.commit()
    return redirect('/admin')

@app.route('/admin/block/<int:user_id>', methods=['POST'])
def block_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect('/')

    reason = request.form.get('reason')

    cursor.execute("SELECT nickname FROM users WHERE id = %s", (user_id,))
    target_user = cursor.fetchone()

    if reason:
        # 🔒 차단
        cursor.execute("""
            UPDATE users SET is_blocked = TRUE, block_reason = %s
            WHERE id = %s
        """, (reason, user_id))
        log_event('admin', f"관리자가 {target_user['nickname']} (ID {user_id}) 계정을 차단했습니다. 사유: {reason}")
    else:
        # ✅ 차단 해제
        cursor.execute("""
            UPDATE users SET is_blocked = FALSE, block_reason = NULL
            WHERE id = %s
        """, (user_id,))
        log_event('admin', f"관리자가 {target_user['nickname']} (ID {user_id}) 계정 차단을 해제했습니다.")

    conn.commit()
    return redirect('/admin')

@app.route('/admin/items')
def admin_items():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect('/')

    cursor.execute("""
        SELECT items.id, items.title, items.price, items.created_at, users.nickname
        FROM items
        JOIN users ON items.owner_id = users.id
        ORDER BY items.created_at DESC
    """)
    items = cursor.fetchall()
    return render_template("admin_items.html", items=items)

@app.route('/admin/items/delete/<int:item_id>', methods=['POST'])
def admin_delete_item(item_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect('/')

    cursor.execute("DELETE FROM items WHERE id = %s", (item_id,))
    conn.commit()
    return redirect('/admin/items')

@app.route('/admin/logs/dashboard')  # ✅ URL 변경
def logs_dashboard():
    if not session.get('is_admin'):
        return "접근 권한 없음", 403

    cursor.execute("SELECT * FROM chat_logs ORDER BY timestamp DESC LIMIT 100")
    chat_logs = cursor.fetchall()

    cursor.execute("SELECT * FROM item_logs ORDER BY timestamp DESC LIMIT 100")
    item_logs = cursor.fetchall()

    cursor.execute("SELECT * FROM report_logs ORDER BY timestamp DESC LIMIT 100")
    report_logs = cursor.fetchall()

    return render_template("admin_logs.html",
                           chat_logs=chat_logs,
                           item_logs=item_logs,
                           report_logs=report_logs)
    
@app.route('/admin/logs')
def admin_logs():
    if not session.get('is_admin'):
        return redirect('/')

    cursor.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100")
    logs = cursor.fetchall()
    
    # 각 로그 테이블에서 데이터를 가져오기
    cursor.execute("SELECT * FROM chat_logs ORDER BY timestamp DESC LIMIT 10")
    chat_logs = cursor.fetchall()

    cursor.execute("SELECT * FROM item_logs ORDER BY timestamp DESC LIMIT 10")
    item_logs = cursor.fetchall()

    cursor.execute("SELECT * FROM report_logs ORDER BY timestamp DESC LIMIT 10")
    report_logs = cursor.fetchall()

    return render_template("admin_logs.html", logs=logs, 
                           chat_logs=chat_logs, 
                           item_logs=item_logs, 
                           report_logs=report_logs)  # ✅ 이게 꼭 있어야 함!

@app.route('/admin/logs/chat')
def chat_logs():
    if not session.get('is_admin'):
        return redirect('/')
    cursor.execute("""
        SELECT c.*, u1.nickname AS sender_name, u2.nickname AS receiver_name
        FROM chat_logs c
        JOIN users u1 ON c.sender_id = u1.id
        JOIN users u2 ON c.receiver_id = u2.id
        ORDER BY c.timestamp DESC
    """)
    logs = cursor.fetchall()
    return render_template('log_chat.html', logs=logs)

@app.route('/admin/logs/items')
def item_logs():
    if not session.get('is_admin'):
        return redirect('/')

    cursor.execute("""
        SELECT il.*, u.nickname
        FROM item_logs il
        JOIN users u ON il.user_id = u.id
        ORDER BY il.timestamp DESC
    """)
    logs = cursor.fetchall()
    return render_template('log_items.html', logs=logs)

@app.route('/admin/logs/reports')
def report_logs():
    if not session.get('is_admin'):
        return redirect('/')
    cursor.execute("""
        SELECT r.*, u1.nickname AS reporter_name, u2.nickname AS reported_name
        FROM report_logs r
        JOIN users u1 ON r.reporter_id = u1.id
        JOIN users u2 ON r.reported_user_id = u2.id
        ORDER BY r.timestamp DESC
    """)
    logs = cursor.fetchall()
    return render_template('log_reports.html', logs=logs)

@app.route('/admin/logs/chat/<int:log_id>', methods=['POST'])
def delete_chat_log(log_id):
    # 관리자만 접근 가능
    if not session.get('is_admin'):
        return "⛔️ 관리자만 접근 가능", 403

    # chat_logs에서 log_id에 해당하는 로그 가져오기
    cursor.execute("SELECT log_type FROM chat_logs WHERE id = %s", (log_id,))
    log = cursor.fetchone()

    if not log:
        return "로그를 찾을 수 없습니다.", 404

    # 로그 유형에 따라 삭제할 테이블을 결정
    cursor.execute("DELETE FROM chat_logs WHERE id = %s", (log_id,))
    conn.commit()
    if session.get('is_superadmin'):
        log_event('admin', f"🗑 슈퍼 관리자가 채팅 로그 ID {log_id} 삭제")
    else:
        nickname = session.get('nickname', '알 수 없음')
        log_event('admin', f"👮‍♀️ 일반 관리자 {nickname}님이 채팅 로그 ID {log_id} 삭제")
    
    return redirect('/admin/logs/chat')

@app.route('/admin/logs/items/<int:log_id>', methods=['POST'])
def delete_items_log(log_id):
    # 관리자만 접근 가능
    if not session.get('is_admin'):
        return "⛔️ 관리자만 접근 가능", 403

    # chat_logs에서 log_id에 해당하는 로그 가져오기
    cursor.execute("SELECT log_type FROM item_logs WHERE id = %s", (log_id,))
    log = cursor.fetchone()

    if not log:
        return "로그를 찾을 수 없습니다.", 404

    # 로그 유형에 따라 삭제할 테이블을 결정
    cursor.execute("DELETE FROM item_logs WHERE id = %s", (log_id,))
    conn.commit()
    if session.get('is_superadmin'):
        log_event('admin', f"🗑 슈퍼 관리자가 게시물 작업 로그 ID {log_id} 삭제")
    else:
        nickname = session.get('nickname', '알 수 없음')
        log_event('admin', f"👮‍♀️ 일반 관리자 {nickname}님이 게시물 작업 로그 ID {log_id} 삭제")
    
    return redirect('/admin/logs/items')

@app.route('/admin/logs/reports/<int:log_id>', methods=['POST'])
def delete_reports_log(log_id):
    # 관리자만 접근 가능
    if not session.get('is_admin'):
        return "⛔️ 관리자만 접근 가능", 403

    # chat_logs에서 log_id에 해당하는 로그 가져오기
    cursor.execute("SELECT log_type FROM report_logs WHERE id = %s", (log_id,))
    log = cursor.fetchone()

    if not log:
        return "로그를 찾을 수 없습니다.", 404

    # 로그 유형에 따라 삭제할 테이블을 결정
    cursor.execute("DELETE FROM report_logs WHERE id = %s", (log_id,))
    conn.commit()
    if session.get('is_superadmin'):
        log_event('admin', f"🗑 슈퍼 관리자가 신고 로그 ID {log_id} 삭제")
    else:
        nickname = session.get('nickname', '알 수 없음')
        log_event('admin', f"👮‍♀️ 일반 관리자 {nickname}님이 신고 로그 ID {log_id} 삭제")
    
    return redirect('/admin/logs/reports')

@app.route('/admin/logs/chat/delete_all', methods=['POST'])
def delete_all_chat_logs():
    if not session.get('is_superadmin'):
        return "권한 없음", 403
    cursor.execute("DELETE FROM chat_logs")
    conn.commit()
    log_event('admin', '슈퍼관리자가 전체 채팅 로그를 삭제함')
    return redirect('/admin/logs/chat')


@app.route('/admin/logs/items/delete_all', methods=['POST'])
def delete_all_item_logs():
    if not session.get('is_superadmin'):
        return "권한 없음", 403
    cursor.execute("DELETE FROM item_logs")
    conn.commit()
    log_event('admin', '슈퍼관리자가 전체 게시물 로그를 삭제함')
    return redirect('/admin/logs/items')


@app.route('/admin/logs/reports/delete_all', methods=['POST'])
def delete_all_report_logs():
    if not session.get('is_superadmin'):
        return "권한 없음", 403
    cursor.execute("DELETE FROM report_logs")
    conn.commit()
    log_event('admin', '슈퍼관리자가 전체 신고 로그를 삭제함')
    return redirect('/admin/logs/reports')

@app.route('/admin/users/edit_balance/<int:user_id>', methods=['GET', 'POST'])
def edit_user_balance(user_id):
    # 슈퍼 관리자만 접근 가능
    if not session.get('is_superadmin'):
        return "⛔️ 슈퍼 관리자만 접근 가능합니다.", 403

    # 해당 사용자의 정보 가져오기
    cursor.execute("SELECT id, nickname, balance FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        return "사용자를 찾을 수 없습니다.", 404

    if request.method == 'POST':
        # 새 잔액 값 가져오기
        new_balance = request.form.get('new_balance', type=float)

        # 잔액 값이 올바른지 확인
        if new_balance is None or new_balance < 0:
            return "⛔️ 유효한 잔액을 입력해주세요.", 400

        # 잔액 수정
        cursor.execute("UPDATE users SET balance = %s WHERE id = %s", (new_balance, user_id))
        conn.commit()

        # 잔액 수정 로그 기록
        log_event('admin', f"📝 슈퍼 관리자가 {user['nickname']} (ID: {user_id})의 잔액을 {new_balance}원으로 수정했습니다.")

        # 수정 후 관리자 페이지로 리다이렉트
        return redirect('/admin')

    # GET 요청 시 사용자의 잔액 수정 페이지 보여주기
    return render_template('edit_balance.html', user=user)

@app.route('/admin/purchases')
def admin_purchases():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect('/')

    cursor.execute("""
        SELECT p.id, u.nickname, i.title, p.purchase_date
        FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN items i ON p.item_id = i.id
        ORDER BY p.purchase_date DESC
    """)
    purchases = cursor.fetchall()

    return render_template('admin_purchases.html', purchases=purchases)

#################### 일반 페이지 ####################

@app.route('/', methods=['GET', 'POST'])
def home():
    search_query = request.args.get('search', '')  # 검색어 받기

    if search_query:
        # 검색어가 있을 경우, 제목과 설명을 기준으로 검색
        cursor.execute("""
            SELECT * FROM items
            WHERE (LOWER(title) LIKE %s OR LOWER(description) LIKE %s) AND is_blocked = 0
        """, (f'%{search_query.lower()}%', f'%{search_query.lower()}%'))
    else:
        # 검색어가 없을 경우, 모든 게시물 가져오기
        cursor.execute("SELECT * FROM items WHERE is_blocked = 0")

    items = cursor.fetchall()  # 검색된 게시물 리스트

    return render_template('index.html', items=items)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], pw):
            if user['is_blocked']:
                # 차단되었지만 로그인은 막지 않음
                session['temp_user'] = {
                    'id': user['id'],
                    'nickname': user['nickname'],
                    'is_admin': user['is_admin']
                }
                return render_template('login.html', blocked=True)

            # 정상 로그인
            session['user_id'] = user['id']
            session['nickname'] = user['nickname']
            session['is_admin'] = user['is_admin']
            session['is_superadmin'] = user.get('is_superadmin', False)
            return redirect('/')
        else:
            return render_template('login.html', error="이메일 또는 비밀번호가 틀렸습니다.")

    return render_template('login.html')

@app.route('/continue_login')
def continue_login():
    temp = session.get('temp_user')
    if not temp:
        return redirect('/login')

    session['user_id'] = temp['id']
    session['nickname'] = temp['nickname']
    session['is_admin'] = temp['is_admin']

    # ✅ 차단된 유저임을 명확히 표시
    cursor.execute("SELECT is_blocked FROM users WHERE id = %s", (temp['id'],))
    result = cursor.fetchone()
    if result and result['is_blocked']:
        session['is_blocked'] = True
    session.pop('temp_user', None)

    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        nickname = request.form['nickname']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return render_template('register.html', error="이미 존재하는 이메일입니다.")

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO users (email, password, nickname) VALUES (%s, %s, %s)", (email, hashed_pw, nickname))
        conn.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/send_money', methods=['GET', 'POST'])
def send_money():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        sender_id = session['user_id']
        receiver_email = request.form['receiver_email']
        amount = float(request.form['amount'])

        # 송금자가 충분한 잔액을 가지고 있는지 확인
        cursor.execute("SELECT balance FROM users WHERE id = %s", (sender_id,))
        sender = cursor.fetchone()
        if sender['balance'] < amount:
            return render_template('send_money.html', error="잔액이 부족합니다.")

        # 수취인 확인
        cursor.execute("SELECT id, balance FROM users WHERE email = %s", (receiver_email,))
        receiver = cursor.fetchone()
        if not receiver:
            return render_template('send_money.html', error="수취인 정보가 없습니다.")

        receiver_id = receiver['id']

        # 송금 처리: 송금자의 계좌에서 금액 차감, 수취인의 계좌에서 금액 추가
        cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (amount, sender_id))
        cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (amount, receiver_id))
        conn.commit()

        # 송금 내역 기록
        cursor.execute("""
            INSERT INTO transactions (sender_id, receiver_id, amount)
            VALUES (%s, %s, %s)
        """, (sender_id, receiver_id, amount))
        conn.commit()

        # 송금 성공 후 알림
        socketio.emit('new_transaction', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'amount': amount
        }, namespace='/')  # 실시간으로 송금 내역을 클라이언트에 전송

        return redirect('/mypage')  # 송금 후 마이 페이지로 리디렉션

    return render_template('send_money.html')

@app.route('/mypage')
def mypage():
    if 'user_id' not in session:
        return redirect('/login')  # 로그인하지 않으면 로그인 페이지로 리디렉션

    # 로그인한 사용자의 정보 가져오기
    user_id = session['user_id']
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    # 사용자가 등록한 상품 목록 가져오기
    cursor.execute("SELECT * FROM items WHERE owner_id = %s AND is_blocked = 0", (user_id,))
    items = cursor.fetchall()

    return render_template('mypage.html', user=user, items=items)

@app.route('/items/<int:item_id>')
def item_detail(item_id):
    cursor.execute("""
        SELECT items.*, users.nickname, users.is_blocked
        FROM items
        JOIN users ON items.owner_id = users.id
        WHERE items.id = %s
    """, (item_id,))
    item = cursor.fetchone()

    if not item:
        return "해당 상품을 찾을 수 없습니다.", 404

    return render_template("item_detail.html", item=item)

@app.route('/items/new', methods=['GET', 'POST'])
def new_item():
    if 'user_id' not in session:
        return redirect('/login')

    cursor.execute("SELECT is_blocked FROM users WHERE id = %s", (session['user_id'],))
    result = cursor.fetchone()
    if result and result['is_blocked']:
        return "⛔️ 차단된 계정은 상품을 등록할 수 없습니다.", 403

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        owner_id = session['user_id']

        image_files = request.files.getlist('images')  # ✅ 여러 이미지
        image_paths = []
        image_path = None  # 대표 이미지

        for img in image_files:
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.save(save_path)
                full_path = '/' + save_path
                image_paths.append(full_path)
                if not image_path:
                    image_path = full_path  # 대표 이미지 1장만

        image_paths_str = ','.join(image_paths) if image_paths else None

        cursor.execute("""
            INSERT INTO items (title, description, price, owner_id, image_path, image_paths)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (title, description, price, owner_id, image_path, image_paths_str))
        conn.commit()

        item_id = cursor.lastrowid

        socketio.emit('new_item', {
            'item_id': item_id,
            'title': title,
            'description': description,
            'price': price,
            'owner_id': owner_id
        }, namespace='/')

        log_item_action(owner_id, item_id, 'create', f'{session["nickname"]}님이 "{title}" 상품을 등록했습니다.')

        return redirect('/')

    return render_template('new_item.html')

@app.route('/items/delete/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' not in session:
        return redirect('/login')

    cursor.execute("SELECT owner_id FROM items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    # 게시물 정보 확인
    cursor.execute("SELECT title, owner_id FROM items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    # 게시물 삭제
    cursor.execute("DELETE FROM items WHERE id = %s", (item_id,))
    conn.commit()

    # 삭제 후 로그 처리
    log_item_action(session['user_id'], item_id, 'delete', f'"{item["title"]}" 상품을 삭제했습니다.')

    cursor.execute("""
        INSERT INTO item_logs (user_id, item_id, action_type, description)
        VALUES (%s, %s, 'delete', %s)
    """, (session['user_id'], item_id, f'상품 "{item["title"]}" 삭제'))
    conn.commit()

    # 실시간 삭제 이벤트 발생
    socketio.emit('delete_item', {
        'item_id': item_id
    }, namespace='/')  # 기본 네임스페이스에 실시간 삭제 이벤트 발송

    # 삭제 권한이 없으면 반환
    if not item or item['owner_id'] != session['user_id']:
        return "삭제 권한이 없습니다.", 403

    # 삭제가 끝난 후
    return redirect('/')

@app.route('/items/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    if 'user_id' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    if not item or item['owner_id'] != session['user_id']:
        return "수정 권한이 없습니다.", 403

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        cursor.execute("""
            UPDATE items
            SET title = %s, description = %s, price = %s
            WHERE id = %s
        """, (title, description, price, item_id))
        conn.commit()

        # 수정 로그 기록
        log_item_action(session['user_id'], item_id, 'update', f'"{title}" 상품을 수정했습니다.')

        return redirect('/')

    return render_template('edit_item.html', item=item)

@app.route('/search', methods=['GET', 'POST'])
def search_results():
    search_query = request.args.get('search', '')  # GET 파라미터로 받은 검색어

    if search_query:
        # 검색어가 있을 경우, 제목과 설명을 기준으로 검색
        cursor.execute("""
            SELECT * FROM items
            WHERE (title LIKE %s OR description LIKE %s) AND is_blocked = 0
        """, (f'%{search_query}%', f'%{search_query}%'))
    else:
        # 검색어가 없으면 모든 게시물을 보여줍니다.
        cursor.execute("SELECT * FROM items WHERE is_blocked = 0")

    items = cursor.fetchall()  # 검색된 게시물 리스트

    return render_template('search_results.html', items=items, search_query=search_query)



@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
def chat(receiver_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    sender_id = session['user_id']
    item_id = request.args.get('item_id', type=int)
    

    item = None
    if item_id:
        cursor.execute("SELECT id, title, owner_id FROM items WHERE id = %s", (item_id,))
        item = cursor.fetchone()

    if request.method == 'POST':
        content = request.form['content']
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content, item_id)
            VALUES (%s, %s, %s, %s)
        """, (sender_id, receiver_id, content, item_id))
        conn.commit()
        return redirect(f'/chat/{receiver_id}?item_id={item_id}')

    cursor.execute("""
        SELECT m.*, u.nickname AS sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ((sender_id = %s AND receiver_id = %s)
            OR (sender_id = %s AND receiver_id = %s))
        AND item_id = %s
        ORDER BY timestamp ASC
    """, (sender_id, receiver_id, receiver_id, sender_id, item_id))
    messages = cursor.fetchall()

    cursor.execute("SELECT nickname, is_blocked FROM users WHERE id = %s", (receiver_id,))
    user = cursor.fetchone()

    return render_template("chat.html", messages=messages, user=user, receiver_id=receiver_id, item=item, item_id=item_id)

@app.route('/chatbox')
def chatbox():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    cursor.execute("""
        SELECT 
            u.id AS user_id, u.nickname, u.is_blocked,
            i.title AS item_title, m.item_id,
            MAX(m.timestamp) AS last_time
        FROM messages m
        JOIN users u ON 
            (u.id = m.sender_id AND m.receiver_id = %s AND m.deleted_by_receiver = FALSE)
            OR 
            (u.id = m.receiver_id AND m.sender_id = %s AND m.deleted_by_sender = FALSE)
        JOIN items i ON m.item_id = i.id
        WHERE u.id != %s
        GROUP BY u.id, u.nickname, u.is_blocked, i.title, m.item_id
        ORDER BY last_time DESC
    """, (user_id, user_id, user_id))

    chats = cursor.fetchall()
    return render_template("chatbox.html", chats=chats)


@app.route('/chat/delete/<int:receiver_id>', methods=['POST'])
def delete_chat(receiver_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    item_id = request.args.get('item_id', type=int)

    if not item_id:
        return "item_id 없음", 400

    # soft delete
    cursor.execute("""
        UPDATE messages
        SET deleted_by_sender = TRUE
        WHERE sender_id = %s AND receiver_id = %s AND item_id = %s 
    """, (user_id, receiver_id, item_id))
    cursor.execute("""
        UPDATE messages
        SET deleted_by_receiver = TRUE
        WHERE sender_id = %s AND receiver_id = %s AND item_id = %s
    """, (receiver_id, user_id, item_id))

    conn.commit()

    return redirect('/chatbox')

@app.route('/report/<int:reported_user_id>', methods=['POST'])
def report_user(reported_user_id):
    if 'user_id' not in session:
        return redirect('/login')

    reporter_id = session['user_id']
    reason = request.form.get('reason')  # 신고 사유
    item_id = request.form.get('item_id', type=int)  # 신고된 게시물의 ID ⬅️ 여기가 중요

    # 게시물 제목을 가져옵니다.
    cursor.execute("SELECT title FROM items WHERE id = %s", (item_id,))
    reported_item = cursor.fetchone()
    reported_item_title = reported_item['title'] if reported_item else '제목 없음'

    if not reason:
        return "신고 사유가 필요합니다.", 400

    # log_report 함수 호출 시 모든 인자를 넘겨줍니다.
    log_report('report', reporter_id, reported_user_id, reason, reported_item_title, item_id)

    return redirect('/')

@app.route('/buy/<int:item_id>', methods=['GET', 'POST'])
def buy_item(item_id):
    if 'user_id' not in session:
        return redirect('/login')  # 로그인하지 않으면 로그인 페이지로 리디렉션

    # 해당 상품 정보 가져오기
    cursor.execute("SELECT * FROM items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    if not item:
        return "상품을 찾을 수 없습니다.", 404

    if request.method == 'POST':
        buyer_id = session['user_id']

        # 구매자가 충분한 잔액을 가지고 있는지 확인
        cursor.execute("SELECT balance FROM users WHERE id = %s", (buyer_id,))
        buyer = cursor.fetchone()

        if buyer['balance'] < item['price']:
            return render_template('buy_item.html', item=item, error="잔액이 부족합니다.")

        # 구매 처리: 구매자의 계좌에서 금액 차감, 판매자의 계좌로 금액 추가
        cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (item['price'], buyer_id))
        cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (item['price'], item['owner_id']))
        conn.commit()

        # 거래 내역 기록
        cursor.execute("""
            INSERT INTO transactions (sender_id, receiver_id, amount)
            VALUES (%s, %s, %s)
        """, (buyer_id, item['owner_id'], item['price']))
        conn.commit()

        # 구매 후 리디렉션
        return redirect('/mypage')

    return render_template('buy_item.html', item=item)

#################### 핸들 ####################

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    item_id = data['item_id']
    content = data['content']

    cursor.execute("SELECT nickname FROM users WHERE id = %s", (sender_id,))
    sender = cursor.fetchone()
    sender_name = sender['nickname'] if sender else '익명'

    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, content, item_id)
        VALUES (%s, %s, %s, %s)
    """, (sender_id, receiver_id, content, item_id))
    conn.commit()

    # 판매자가 보낸 메시지일 경우에만 '상품 구매하기' 버튼을 전송
    cursor.execute("SELECT owner_id FROM items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    # 판매자만 버튼을 보낼 수 있도록 설정
    if sender_id == item['owner_id']:  # 판매자일 경우만 버튼 전송
        # '상품 구매하기' 버튼을 별도로 전송
        purchase_button = {
            'item_id': item_id,
            'content': f"상품 구매하기 버튼 클릭"
        }
        socketio.emit('purchase_button', purchase_button, room=receiver_id)  # 구매 버튼만 전송

    # 채팅 기록을 chat_logs에 저장
    cursor.execute("""
        INSERT INTO chat_logs (sender_id, receiver_id, item_id, content)
        VALUES (%s, %s, %s, %s)
    """, (sender_id, receiver_id, item_id, content))
    conn.commit()

    log_event('chat', f"[채팅] {sender_name} → {receiver_id}: {content}")

    # 채팅 메시지 전송 (새로운 메시지 전송)
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM messages
        WHERE ((sender_id = %s AND receiver_id = %s)
            OR (sender_id = %s AND receiver_id = %s))
          AND item_id = %s
    """, (sender_id, receiver_id, receiver_id, sender_id, item_id))
    count = cursor.fetchone()['cnt']
    if count == 1:
        socketio.emit('new_chat', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'item_id': item_id
        })

    # 클라이언트에게 메시지 전송
    emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'item_id': item_id,
        'sender_name': sender_name,
        'content': content
    }, broadcast=True)
    

@socketio.on('delete_message')
def handle_delete_message(data):
    msg_id = data.get('id')
    user_id = session.get('user_id')

    cursor.execute("SELECT sender_id FROM messages WHERE id = %s", (msg_id,))
    result = cursor.fetchone()
    if not result or result['sender_id'] != user_id:
        return

    cursor.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
    conn.commit()
    emit('message_deleted', { 'id': msg_id }, broadcast=True)
    
@socketio.on('new_log')
def handle_new_log(data):
    print(f"Received data: {data}")  # 로그로 확인
    if data['log_type'] == 'report':
        reported_item_title = data.get('reported_item_title', '제목 없음')
        reported_item_id = data.get('reported_item_id', 'ID 없음')  # ID가 제대로 넘어오는지 확인
        reason = data.get('reason', '사유 없음')
        reporter_name = data.get('reporter_name', '알 수 없음')

        cursor.execute("""
            INSERT INTO report_logs (reporter_id, reported_item_id, reported_item_title, reason)
            VALUES (%s, %s, %s, %s)
        """, (data['reporter_id'], reported_item_id, reported_item_title, reason))
        conn.commit()

        # 실시간 알림
        socketio.emit('new_log', {
            'log_type': 'report',
            'reporter_name': reporter_name,
            'reported_item_title': reported_item_title,
            'reported_item_id': reported_item_id,
            'reason': reason,
            'timestamp': str(datetime.now())
        }, namespace='/admin')
        
@socketio.on('send_purchase_button')
def handle_send_purchase_button(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    item_id = data['item_id']

    print(f"상품 구매 버튼을 보냅니다: sender_id={sender_id}, receiver_id={receiver_id}, item_id={item_id}")

    # ✅ 반드시 문자열로
    socketio.emit('purchase_button', {'item_id': item_id}, room=str(receiver_id))
    
#################### 연결 ####################

@socketio.on('connect', namespace='/admin')
def handle_admin_connect():
    print("✅ 관리자 소켓 연결됨")

@socketio.on('join')
def on_join(data):
    user_id = data['user_id']
    join_room(str(user_id))  # 반드시 str로!
    print(f"사용자 {user_id} 가 room {user_id} 에 입장했습니다.")
    
#################### 실행 ####################

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080, use_reloader=False)