from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_restx import Api, Resource, fields, Namespace
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
import os

app = Flask(__name__)

# Включаем CORS для всех доменов
CORS(app)

# Конфигурация
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:qwe123@localhost/news_site'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-this'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Настройка авторизации для Swagger
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Введите JWT токен в формате: Bearer <your_token>'
    }
}

# Инициализация API с Swagger и JWT поддержкой
api = Api(
    app, 
    version='1.0', 
    title='News Site API',
    description='REST API для новостного сайта с JWT аутентификацией',
    doc='/swagger/',
    default='News API',
    default_label='Основные методы API',
    authorizations=authorizations,
    security='Bearer Auth'
)

# Инициализация расширений
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Модели для Swagger документации
login_model = api.model('Login', {
    'username': fields.String(required=True, description='Имя пользователя', example='testuser'),
    'password': fields.String(required=True, description='Пароль', example='testpassword')
})

register_model = api.model('Register', {
    'username': fields.String(required=True, description='Имя пользователя', example='newuser'),
    'email': fields.String(required=True, description='Email', example='user@example.com'),
    'password': fields.String(required=True, description='Пароль', example='securepassword')
})

post_model = api.model('Post', {
    'title': fields.String(required=True, description='Заголовок поста', example='Новая новость'),
    'content': fields.String(required=True, description='Содержание поста', example='Текст новости...'),
    'category_id': fields.Integer(required=True, description='ID категории', example=1)
})

post_update_model = api.model('PostUpdate', {
    'title': fields.String(description='Заголовок поста', example='Обновленный заголовок'),
    'content': fields.String(description='Содержание поста', example='Обновленный текст...'),
    'category_id': fields.Integer(description='ID категории', example=2)
})

like_response_model = api.model('LikeResponse', {
    'message': fields.String,
    'liked': fields.Boolean,
    'likes_count': fields.Integer,
    'user_id': fields.Integer,
    'post_id': fields.Integer
})

like_info_model = api.model('LikeInfo', {
    'post_id': fields.Integer,
    'likes_count': fields.Integer,
    'user_liked': fields.Boolean,
    'post_title': fields.String
})

user_likes_model = api.model('UserLikes', {
    'user_id': fields.Integer,
    'total_likes': fields.Integer,
    'liked_posts': fields.List(fields.Raw)
})

change_password_model = api.model('ChangePassword', {
    'current_password': fields.String(required=True, description='Текущий пароль', example='oldpassword'),
    'new_password': fields.String(required=True, description='Новый пароль', example='newpassword123')
})

admin_like_model = api.model('AdminLike', {
    'user_id': fields.Integer(required=True, description='ID пользователя', example=1),
    'post_id': fields.Integer(required=True, description='ID поста', example=1)
})

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    
    posts = db.relationship('Post', backref='category', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    likes = db.relationship('Like', backref='post', lazy=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)

# Создание таблиц и тестовых данных
def init_database():
    with app.app_context():
        try:
            db.create_all()
            
            if Category.query.count() == 0:
                categories = [
                    Category(name="Политика"),
                    Category(name="Спорт"),
                    Category(name="Технологии"),
                    Category(name="Культура"),
                    Category(name="Экономика")
                ]
                db.session.bulk_save_objects(categories)
                db.session.commit()
                print("✅ Категории созданы")
            
            if User.query.filter_by(username='testuser').first() is None:
                test_user = User(username='testuser', email='test@example.com')
                test_user.set_password('testpassword')
                db.session.add(test_user)
                db.session.commit()
                print("✅ Тестовый пользователь создан: testuser / testpassword")
            
            if User.query.filter_by(username='admin').first() is None:
                admin_user = User(username='admin', email='admin@example.com')
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Админ пользователь создан: admin / admin123")
            
            if Post.query.count() == 0 and User.query.filter_by(username='testuser').first():
                test_user = User.query.filter_by(username='testuser').first()
                test_post = Post(
                    title='Тестовый пост',
                    content='Это тестовый пост для проверки API',
                    category_id=1,
                    user_id=test_user.id
                )
                db.session.add(test_post)
                db.session.commit()
                print("✅ Тестовый пост создан")
                
        except Exception as e:
            print(f"❌ Ошибка инициализации БД: {e}")

# Инициализация базы данных
init_database()

# Вспомогательные функции
def post_to_dict(post):
    return {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'category_id': post.category_id,
        'category_name': post.category.name if post.category else None,
        'author': post.author.username if post.author else None,
        'author_id': post.user_id,
        'likes_count': len(post.likes),
        'created_at': post.created_at.isoformat(),
        'updated_at': post.updated_at.isoformat()
    }

# Namespace для аутентификации
auth_ns = Namespace('auth', description='Операции аутентификации')
api.add_namespace(auth_ns)

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @auth_ns.response(201, 'Успех')
    @auth_ns.response(400, 'Ошибка')
    def post(self):
        """Регистрация нового пользователя"""
        try:
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            
            if not username or not email or not password:
                return {'message': 'Все поля обязательны для заполнения'}, 400
            
            if User.query.filter_by(username=username).first():
                return {'message': 'Имя пользователя уже существует'}, 400
            
            if User.query.filter_by(email=email).first():
                return {'message': 'Email уже используется'}, 400
            
            user = User(username=username, email=email)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            return {
                'message': 'Пользователь успешно создан',
                'user_id': user.id,
                'username': user.username
            }, 201
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Успех')
    @auth_ns.response(400, 'Ошибка валидации')
    @auth_ns.response(401, 'Неверные данные')
    def post(self):
        """Аутентификация пользователя и получение JWT токена"""
        try:
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return {'message': 'Имя пользователя и пароль обязательны'}, 400
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                access_token = create_access_token(identity=str(user.id))
                
                return {
                    'message': 'Вход выполнен успешно',
                    'token': access_token,
                    'user_id': user.id,
                    'username': user.username
                }, 200
            
            return {'message': 'Неверное имя пользователя или пароль'}, 401
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

@auth_ns.route('/change-password')
class ChangePassword(Resource):
    @auth_ns.expect(change_password_model)
    @auth_ns.response(200, 'Пароль успешно изменен')
    @auth_ns.response(400, 'Ошибка валидации')
    @auth_ns.response(401, 'Неверный текущий пароль')
    @auth_ns.doc(security='Bearer Auth')
    @jwt_required()
    def post(self):
        """Изменение пароля пользователя"""
        try:
            current_user_id = int(get_jwt_identity())
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            
            if not current_password or not new_password:
                return {'message': 'Текущий и новый пароль обязательны'}, 400
            
            if len(new_password) < 6:
                return {'message': 'Новый пароль должен содержать минимум 6 символов'}, 400
            
            user = User.query.get(current_user_id)
            if not user:
                return {'message': 'Пользователь не найден'}, 404
            
            if not user.check_password(current_password):
                return {'message': 'Неверный текущий пароль'}, 401
            
            user.set_password(new_password)
            db.session.commit()
            
            return {
                'message': 'Пароль успешно изменен',
                'user_id': user.id,
                'username': user.username
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

# Namespace для постов
posts_ns = Namespace('posts', description='Операции с постами')
api.add_namespace(posts_ns)

@posts_ns.route('/')
class PostList(Resource):
    @posts_ns.doc(params={
        'page': {'description': 'Номер страницы', 'type': 'int', 'default': 1},
        'per_page': {'description': 'Количество постов на странице', 'type': 'int', 'default': 10},
        'category': {'description': 'ID категории для фильтрации', 'type': 'int'}
    })
    @posts_ns.response(200, 'Успешное получение списка постов')
    def get(self):
        """Получить список постов с пагинацией и фильтрацией"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        category_id = request.args.get('category', type=int)
        
        query = Post.query
        
        if category_id:
            query = query.filter_by(category_id=category_id)
        
        posts_pagination = query.order_by(Post.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        posts_data = [post_to_dict(post) for post in posts_pagination.items]
        
        return {
            'posts': posts_data,
            'total_pages': posts_pagination.pages,
            'current_page': page,
            'total_posts': posts_pagination.total
        }, 200

    @posts_ns.expect(post_model)
    @posts_ns.response(201, 'Пост успешно создан')
    @posts_ns.response(400, 'Ошибка валидации')
    @posts_ns.response(401, 'Требуется аутентификация')
    @posts_ns.doc(security='Bearer Auth')
    @jwt_required()
    def post(self):
        """Создать новый пост (требуется аутентификация)"""
        try:
            current_user_id = int(get_jwt_identity())
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            title = data.get('title')
            content = data.get('content')
            category_id = data.get('category_id')
            
            if not title or not content or not category_id:
                return {'message': 'Все поля обязательны для заполнения'}, 400
            
            category = Category.query.get(category_id)
            if not category:
                return {'message': 'Категория не найдена'}, 400
            
            post = Post(
                title=title,
                content=content,
                category_id=category_id,
                user_id=current_user_id
            )
            
            db.session.add(post)
            db.session.commit()
            
            return {
                'message': 'Пост успешно создан',
                'post': post_to_dict(post)
            }, 201
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

@posts_ns.route('/<int:post_id>')
@posts_ns.param('post_id', 'ID поста')
class PostDetail(Resource):
    @posts_ns.response(200, 'Пост найден')
    @posts_ns.response(404, 'Пост не найден')
    def get(self, post_id):
        """Получить пост по ID"""
        post = Post.query.get(post_id)
        if not post:
            return {'message': 'Пост не найден'}, 404
        return post_to_dict(post), 200

    @posts_ns.expect(post_update_model)
    @posts_ns.response(200, 'Пост обновлен')
    @posts_ns.response(403, 'Нет прав для редактирования')
    @posts_ns.response(404, 'Пост не найден')
    @posts_ns.doc(security='Bearer Auth')
    @jwt_required()
    def put(self, post_id):
        """Обновить пост (требуется аутентификация и права автора)"""
        try:
            current_user_id = int(get_jwt_identity())
            post = Post.query.get(post_id)
            
            if not post:
                return {'message': 'Пост не найден'}, 404
            
            if post.user_id != current_user_id:
                return {'message': 'Нет прав для редактирования этого поста'}, 403
            
            data = request.get_json()
            
            if 'title' in data and data['title']:
                post.title = data['title']
            if 'content' in data and data['content']:
                post.content = data                                                                                                                                                                                ['content']
            if 'category_id' in data:
                category = Category.query.get(data['category_id'])
                if not category:
                    return {'message': 'Категория не найдена'}, 400
                post.category_id = data['category_id']
            
            post.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            
            return {
                'message': 'Пост успешно обновлен',
                'post': post_to_dict(post)
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

    @posts_ns.response(200, 'Пост удален')
    @posts_ns.response(403, 'Нет прав для удаления')
    @posts_ns.response(404, 'Пост не найден')
    @posts_ns.doc(security='Bearer Auth')
    @jwt_required()
    def delete(self, post_id):
        """Удалить пост (требуется аутентификация и права автора)"""
        try:
            current_user_id = int(get_jwt_identity())
            post = Post.query.get(post_id)
            
            if not post:
                return {'message': 'Пост не найден'}, 404
            
            if post.user_id != current_user_id:
                return {'message': 'Нет прав для удаления этого поста'}, 403
            
            Like.query.filter_by(post_id=post_id).delete()
            db.session.delete(post)
            db.session.commit()
            
            return {'message': 'Пост успешно удален'}, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

likes_ns = Namespace('likes', description='Операции с лайками')
api.add_namespace(likes_ns)

@likes_ns.route('/posts/<int:post_id>/like')
@likes_ns.param('post_id', 'ID поста')
class PostLike(Resource):
    @likes_ns.response(200, 'Лайк удален', like_response_model)
    @likes_ns.response(201, 'Лайк поставлен', like_response_model)
    @likes_ns.response(404, 'Пост не найден')
    @likes_ns.doc(security='Bearer Auth')
    @jwt_required()
    def post(self, post_id):
        """Поставить или убрать лайк с поста (для текущего пользователя)"""
        try:
            current_user_id = int(get_jwt_identity())
            
            post = Post.query.get(post_id)
            if not post:
                return {'message': 'Пост не найден'}, 404
            
            existing_like = Like.query.filter_by(
                user_id=current_user_id, 
                post_id=post_id
            ).first()
            
            if existing_like:
                db.session.delete(existing_like)
                db.session.commit()
                
                return {
                    'message': 'Лайк удален',
                    'liked': False,
                    'likes_count': Like.query.filter_by(post_id=post_id).count(),
                    'user_id': current_user_id,
                    'post_id': post_id
                }, 200
            else:
                like = Like(user_id=current_user_id, post_id=post_id)
                db.session.add(like)
                db.session.commit()
                
                return {
                    'message': 'Лайк поставлен',
                    'liked': True,
                    'likes_count': Like.query.filter_by(post_id=post_id).count(),
                    'user_id': current_user_id,
                    'post_id': post_id
                }, 201
                
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

    @likes_ns.response(200, 'Информация о лайках', like_info_model)
    @likes_ns.response(404, 'Пост не найден')
    @likes_ns.doc(security='Bearer Auth')
    @jwt_required()
    def get(self, post_id):
        """Проверить, лайкнул ли пользователь пост и получить количество лайков"""
        try:
            current_user_id = int(get_jwt_identity())
            
            post = Post.query.get(post_id)
            if not post:
                return {'message': 'Пост не найден'}, 404
            
            user_like = Like.query.filter_by(
                user_id=current_user_id, 
                post_id=post_id
            ).first()
            
            return {
                'post_id': post_id,
                'likes_count': len(post.likes),
                'user_liked': user_like is not None,
                'post_title': post.title
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

@likes_ns.route('/users/me')
class UserLikes(Resource):
    @likes_ns.response(200, 'Список лайков пользователя', user_likes_model)
    @likes_ns.doc(security='Bearer Auth')
    @jwt_required()
    def get(self):
        """Получить посты, которые лайкнул текущий пользователь"""
        try:
            current_user_id = int(get_jwt_identity())
            
            user_likes = Like.query.filter_by(user_id=current_user_id).all()
            
            liked_posts = []
            for like in user_likes:
                post_data = post_to_dict(like.post)
                post_data['liked_at'] = like.created_at.isoformat()
                liked_posts.append(post_data)
            
            return {
                'user_id': current_user_id,
                'total_likes': len(liked_posts),
                'liked_posts': liked_posts
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

# Административные методы для управления лайками
@likes_ns.route('/admin/like')
class AdminLikeManagement(Resource):
    @likes_ns.expect(admin_like_model)
    @likes_ns.response(201, 'Лайк поставлен', like_response_model)
    @likes_ns.response(400, 'Ошибка валидации')
    @likes_ns.response(404, 'Пользователь или пост не найден')
    @likes_ns.doc(security='Bearer Auth')
    @jwt_required()
    def post(self):
        """Поставить лайк от имени указанного пользователя"""
        try:
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            user_id = data.get('user_id')
            post_id = data.get('post_id')
            
            if not user_id or not post_id:
                return {'message': 'user_id и post_id обязательны'}, 400
            
            user = User.query.get(user_id)
            if not user:
                return {'message': 'Пользователь не найден'}, 404
            
            post = Post.query.get(post_id)
            if not post:
                return {'message': 'Пост не найден'}, 404
            
            existing_like = Like.query.filter_by(
                user_id=user_id, 
                post_id=post_id
            ).first()
            
            if existing_like:
                return {
                    'message': 'Пользователь уже лайкнул этот пост',
                    'liked': True,
                    'likes_count': Like.query.filter_by(post_id=post_id).count(),
                    'user_id': user_id,
                    'post_id': post_id
                }, 200
            
            like = Like(user_id=user_id, post_id=post_id)
            db.session.add(like)
            db.session.commit()
            
            return {
                'message': 'Лайк успешно поставлен от имени пользователя',
                'liked': True,
                'likes_count': Like.query.filter_by(post_id=post_id).count(),
                'user_id': user_id,
                'post_id': post_id
            }, 201
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

    @likes_ns.expect(admin_like_model)
    @likes_ns.response(200, 'Лайк удален', like_response_model)
    @likes_ns.response(400, 'Ошибка валидации')
    @likes_ns.response(404, 'Лайк не найден')
    @likes_ns.doc(security='Bearer Auth')
    
    @jwt_required()
    def delete(self):
        """Удалить лайк указанного пользователя"""
        try:
            data = request.get_json()
            
            if not data:
                return {'message': 'Отсутствуют данные'}, 400
            
            user_id = data.get('user_id')
            post_id = data.get('post_id')
            
            if not user_id or not post_id:
                return {'message': 'user_id и post_id обязательны'}, 400
            
            like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
            
            if not like:
                return {'message': 'Лайк не найден'}, 404
            
            db.session.delete(like)
            db.session.commit()
            
            return {
                'message': 'Лайк успешно удален',
                'liked': False,
                'likes_count': Like.query.filter_by(post_id=post_id).count(),
                'user_id': user_id,
                'post_id': post_id
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

@likes_ns.route('/admin/user/<int:user_id>/likes')
@likes_ns.param('user_id', 'ID пользователя')
class AdminUserLikes(Resource):
    @likes_ns.response(200, 'Список лайков пользователя')
    @likes_ns.response(404, 'Пользователь не найден')
    @likes_ns.doc(security='Bearer Auth')
    @jwt_required()
    def get(self, user_id):
        """Получить все лайки указанного пользователя"""
        try:
            user = User.query.get(user_id)
            if not user:
                return {'message': 'Пользователь не найден'}, 404
            
            user_likes = Like.query.filter_by(user_id=user_id).all()
            
            liked_posts = []
            for like in user_likes:
                post_data = post_to_dict(like.post)
                post_data['liked_at'] = like.created_at.isoformat()
                liked_posts.append(post_data)
            
            return {
                'user_id': user_id,
                'username': user.username,
                'total_likes': len(liked_posts),
                'liked_posts': liked_posts
            }, 200
            
        except Exception as e:
            return {'message': f'Ошибка сервера: {str(e)}'}, 500

# Namespace для поиска
search_ns = Namespace('search', description='Поиск постов')
api.add_namespace(search_ns)

@search_ns.route('/')
class Search(Resource):
    @search_ns.doc(params={'q': 'Поисковый запрос'})
    @search_ns.response(200, 'Успешный поиск')
    def get(self):
        """Поиск постов по заголовку и содержанию"""
        query = request.args.get('q', '')
        if not query:
            return {'posts': [], 'message': 'Введите поисковый запрос'}, 200
        
        posts = Post.query.filter(
            (Post.title.ilike(f'%{query}%')) | 
            (Post.content.ilike(f'%{query}%'))
        ).order_by(Post.created_at.desc()).all()
        
        posts_data = [post_to_dict(post) for post in posts]
        
        return {
            'posts': posts_data,
            'search_query': query,
            'total_results': len(posts_data)
        }, 200

categories_ns = Namespace('categories', description='Операции с категориями')
api.add_namespace(categories_ns)

@categories_ns.route('/')
class CategoryList(Resource):
    @categories_ns.response(200, 'Успешное получение категорий')
    def get(self):
        """Получить список всех категорий"""
        categories = Category.query.all()
        categories_data = [{'id': cat.id, 'name': cat.name} for cat in categories]
        
        return {
            'categories': categories_data,
            'total_categories': len(categories_data)
        }, 200


@app.route('/health', methods=['GET'])
def health_check():
    """Проверка работоспособности API"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'database': 'MySQL',
        'total_users': User.query.count(),
        'total_posts': Post.query.count(),
        'total_categories': Category.query.count(),
        'total_likes': Like.query.count()
    })

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Отладочный эндпоинт для проверки пользователей"""
    users = User.query.all()
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'created_at': user.created_at.isoformat()
        })
    
    return jsonify({
        'total_users': len(users_data),
        'users': users_data
    })

if __name__ == '__main__':
   
    app.run(debug=True, host='localhost', port=5000)