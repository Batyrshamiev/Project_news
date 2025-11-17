import unittest
import requests
import json
import time
import random

class TestAuthAPI(unittest.TestCase):
    
    BASE_URL = "http://localhost:5000"
    
    def setUp(self):
        """Настройка перед каждым тестом"""
        self.session = requests.Session()
       
        timestamp = int(time.time())
        random_suffix = random.randint(1000, 9999)
        self.test_user = {
            "username": f"testuser_{timestamp}_{random_suffix}",
            "email": f"test{timestamp}_{random_suffix}@example.com", 
            "password": "TestPassword123!"
        }
        
     
        self.existing_user = {
            "username": "testuser",
            "password": "testpassword"
        }
    
    def tearDown(self):
        """Очистка после каждого теста"""
        self.session.close()
    
    
    
    def test_02_successful_registration(self):
        """Тест успешной регистрации нового пользователя"""
        print("\nТест 2: Успешная регистрация")
        response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json=self.test_user
        )
        
        self.assertEqual(response.status_code, 201)
        data = response.json()
     
        self.assertIn("message", data)
        self.assertIn("user_id", data)
        self.assertIn("username", data)

        self.assertEqual(data["message"], "Пользователь успешно создан")
        self.assertEqual(data["username"], self.test_user["username"])
        self.assertIsInstance(data["user_id"], int)
        self.assertGreater(data["user_id"], 0)
        
        print(f"Пользователь {self.test_user['username']} успешно зарегистрирован (ID: {data['user_id']})")
        
       
        self.registered_user_id = data["user_id"]
        self.registered_username = self.test_user["username"]
    
    def test_03_registration_duplicate_username(self):
        """Тест регистрации с существующим именем пользователя"""
        print("\nТест 3: Регистрация с существующим username")
        
      
        response1 = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json=self.test_user
        )
        self.assertEqual(response1.status_code, 201)
        
   
        response2 = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "username": self.test_user["username"],  
                "email": "different@example.com", 
                "password": "differentpassword"
            }
        )
        
        self.assertEqual(response2.status_code, 400)
        data = response2.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Имя пользователя уже существует")
        print("Корректная обработка дубликата username")
    
    def test_04_registration_duplicate_email(self):
        """Тест регистрации с существующим email"""
        print("\nТест 4: Регистрация с существующим email")
        
  
        response1 = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json=self.test_user
        )
        self.assertEqual(response1.status_code, 201)
        
      
        response2 = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "username": "completely_different_user", 
                "email": self.test_user["email"], 
                "password": "differentpassword"
            }
        )
        
        self.assertEqual(response2.status_code, 400)
        data = response2.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Email уже используется")
        print("Корректная обработка дубликата email")
    
    def test_05_registration_missing_fields(self):
        """Тест регистрации с отсутствующими полями"""
        print("\nТест 5: Регистрация с отсутствующими полями")
        
 
        response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "email": "test@example.com",
                "password": "password123"
            }
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Все поля обязательны для заполнения")
        
    
        response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "username": "testuser",
                "password": "password123"
            }
        )
        self.assertEqual(response.status_code, 400)
        
     
        response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com"
            }
        )
        self.assertEqual(response.status_code, 400)
        
        print("Корректная обработка отсутствующих полей")
    
    def test_06_registration_short_password(self):
        """Тест регистрации с коротким паролем"""
        print("\nТест 6: Регистрация с коротким паролем")
        
        response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json={
                "username": "shortpassuser",
                "email": "shortpass@example.com",
                "password": "123" 
            }
        )
        

        if response.status_code == 201:
            print("Пользователь создан (нет валидации длины пароля)")
        else:
            print("API отклоняет короткий пароль")
    
    def test_07_successful_login(self):
        """Тест успешного входа в систему"""
        print("\n Тест 7: Успешный вход в систему")
        
       
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json=self.existing_user
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
      
        self.assertIn("message", data)
        self.assertIn("token", data)
        self.assertIn("user_id", data)
        self.assertIn("username", data)
        
   
        self.assertEqual(data["message"], "Вход выполнен успешно")
        self.assertEqual(data["username"], self.existing_user["username"])
        self.assertIsInstance(data["user_id"], int)
        self.assertGreater(data["user_id"], 0)
        self.assertIsInstance(data["token"], str)
        self.assertGreater(len(data["token"]), 10)  
        
        print(f"Успешный вход пользователя {self.existing_user['username']}")
        

        self.auth_token = data["token"]
        self.user_id = data["user_id"]
    
    def test_08_login_wrong_password(self):
        """Тест входа с неправильным паролем"""
        print("\nТест 8: Вход с неправильным паролем")
        
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "username": self.existing_user["username"],
                "password": "wrong_password"  
            }
        )
        
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Неверное имя пользователя или пароль")
        print("Корректная обработка неправильного пароля")
    
    def test_09_login_nonexistent_user(self):
        """Тест входа с несуществующим пользователем"""
        print("\nТест 9: Вход с несуществующим пользователем")
        
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "username": "nonexistent_user_12345",
                "password": "anypassword"
            }
        )
        
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Неверное имя пользователя или пароль")
        print("Корректная обработка несуществующего пользователя")
    
    def test_10_login_missing_fields(self):
        """Тест входа с отсутствующими полями"""
        print("\nТест 10: Вход с отсутствующими полями")
       
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "password": "password123"
            }
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Имя пользователя и пароль обязательны")
        
      
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "username": "testuser"
            }
        )
        self.assertEqual(response.status_code, 400)
        
        print("Корректная обработка отсутствующих полей при входе")
    
    def test_11_jwt_token_validity(self):
        """Тест валидности JWT токена"""
        print("\nТест 11: Проверка валидности JWT токена")
        
   
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json=self.existing_user
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        token = data["token"]
        
       
        parts = token.split('.')
        self.assertEqual(len(parts), 3, "JWT токен должен состоять из 3 частей")
        
        
        self.assertGreater(len(token), 50, "JWT токен должен быть достаточно длинным")
        
        print("JWT токен имеет правильный формат")
    
    def test_12_registration_and_login_flow(self):
        """Тест полного цикла: регистрация -> вход"""
        print("\nТест 12: Полный цикл регистрация -> вход")
       
        timestamp = int(time.time())
        test_user = {
            "username": f"flowuser_{timestamp}",
            "email": f"flow{timestamp}@example.com",
            "password": "FlowPassword123!"
        }
 
        reg_response = self.session.post(
            f"{self.BASE_URL}/auth/register",
            json=test_user
        )
        self.assertEqual(reg_response.status_code, 201)
        reg_data = reg_response.json()
        
  
        login_response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "username": test_user["username"],
                "password": test_user["password"]
            }
        )
        self.assertEqual(login_response.status_code, 200)
        login_data = login_response.json()

        self.assertEqual(login_data["username"], test_user["username"])
        self.assertEqual(login_data["user_id"], reg_data["user_id"])
        
        print("Полный цикл регистрация->вход работает корректно")
    
    def test_13_multiple_registrations_different_users(self):
        """Тест регистрации нескольких разных пользователей"""
        print("\nТест 13: Регистрация нескольких пользователей")
        
        users = []
        for i in range(3):
            user_data = {
                "username": f"multiuser_{i}_{int(time.time())}",
                "email": f"multi{i}_{int(time.time())}@example.com",
                "password": f"Password{i}!"
            }
            
            response = self.session.post(
                f"{self.BASE_URL}/auth/register",
                json=user_data
            )
            self.assertEqual(response.status_code, 201)
            data = response.json()
            
            users.append({
                "data": user_data,
                "id": data["user_id"]
            })
            print(f"  Пользователь {user_data['username']} создан (ID: {data['user_id']})")
        
     
        user_ids = [user["id"] for user in users]
        self.assertEqual(len(user_ids), len(set(user_ids)), "Все ID пользователей должны быть уникальными")
        
        print("Все пользователи успешно зарегистрированы с уникальными ID")

class TestProtectedEndpoints(unittest.TestCase):
    
    BASE_URL = "http://localhost:5000"
    
    def setUp(self):
        """Настройка перед каждым тестом"""
        self.session = requests.Session()
   
        response = self.session.post(
            f"{self.BASE_URL}/auth/login",
            json={
                "username": "testuser",
                "password": "testpassword"
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.auth_token = data["token"]
        self.user_id = data["user_id"]
    
    
    
    
def run_all_tests():
    """Функция для запуска всех тестов"""
    print("Запуск модульных тестов авторизации и регистрации")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    

    suite.addTests(loader.loadTestsFromTestCase(TestAuthAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestProtectedEndpoints))
  
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("=" * 60)
    print(f" Результаты тестирования:")
    print(f"   Всего тестов: {result.testsRun}")
    print(f"   Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   Провалено: {len(result.failures)}")
    print(f"   Ошибок: {len(result.errors)}")
    
    return result

if __name__ == '__main__':
    run_all_tests()