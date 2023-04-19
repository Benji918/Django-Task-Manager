from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from phonenumber_field.modelfields import PhoneNumberField
from phonenumber_field.phonenumber import PhoneNumber
from faker import Faker
from phonenumbers import PhoneNumberFormat, PhoneNumber, NumberParseException

User = get_user_model()
fake = Faker()


class UserModelTests(TestCase):

    def test_create_user_with_email_successful(self):
        """Test creating a new user with an email is successful"""
        email = fake.email()
        password = fake.password()
        first_name = fake.first_name()
        last_name = fake.last_name()
        phone_number = fake.phone_number()
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number
        )
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertEqual(user.first_name, first_name)
        self.assertEqual(user.last_name, last_name)
        self.assertIsInstance(user.phone_number, PhoneNumber)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_active)

    def test_new_user_email_normalized(self):
        """Test the email for a new user is normalized"""
        email = 'test@TEST.COM'
        user = User.objects.create_user(email, 'test123')
        self.assertEqual(user.email, email.lower())

    def test_new_user_invalid_email(self):
        """Test creating user with no email raises error"""
        with self.assertRaises(ValueError):
            User.objects.create_user(None, 'test123')

    def test_create_new_superuser(self):
        """Test creating a new superuser"""
        email = fake.email()
        password = fake.password()
        first_name = fake.first_name()
        last_name = fake.last_name()
        phone_number = fake.phone_number()
        user = User.objects.create_superuser(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number
        )
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertEqual(user.first_name, first_name)
        self.assertEqual(user.last_name, last_name)
        self.assertIsInstance(user.phone_number, PhoneNumber)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_user_has_email_verified(self):
        """Test user's email_verified field"""
        user = User.objects.create_user(
            email=fake.email(),
            password=fake.password(),
            first_name=fake.first_name(),
            last_name=fake.last_name(),
            phone_number=fake.phone_number(),
            email_verified=True
        )
        self.assertTrue(user.has_email_verified())

    def test_user_has_not_email_verified(self):
        """Test user's email_verified field"""
        user = User.objects.create_user(
            email=fake.email(),
            password=fake.password(),
            first_name=fake.first_name(),
            last_name=fake.last_name(),
            phone_number=fake.phone_number(),
            email_verified=False
        )
        self.assertFalse(user.has_email_verified())

    def test_user_email_verified_default_false(self):
        """Test user's email_verified default field value"""
        user = User.objects.create_user(
            email=fake.email(),
            password=fake.password(),
            first_name=fake.first_name(),
            last_name=fake.last_name(),
            phone_number=fake.phone_number()
        )
        self.assertFalse(user.email_verified)

    def setUp(self):
        self.field = PhoneNumberField()

    def test_phone_number_field(self):
        # Create an instance of the model with a valid phone number
        phone_number = PhoneNumber.from_string("+14155552671")
        instance = User.objects.create(phone_number=phone_number)

        # Verify that the phone number was stored correctly
        self.assertEqual(instance.phone_number, phone_number)

        # Verify that the string representation of the phone number is correct
        self.assertEqual(str(phone_number), "+14155552671")

        # Attempt to create an instance of the model with an invalid phone number
        with self.assertRaises(ValueError):
            User.objects.create(phone_number="invalid-phone-number")



    def test_valid_phone_number(self):
        number = "+2348131234567"
        formatted_number = PhoneNumber.from_string(number).format_as(PhoneNumberFormat.E164)
        value = self.field.clean(formatted_number)
        self.assertEqual(value, formatted_number)

    def test_invalid_phone_number(self):
        number = "invalid_number"
        with self.assertRaises(ValidationError):
            self.field.clean(number)

    def test_blank_phone_number(self):
        value = self.field.clean("")
        self.assertIsNone(value)

    def test_null_phone_number(self):
        value = self.field.clean(None)
        self.assertIsNone(value)

    def test_phone_number_max_length(self):
        max_length_field = PhoneNumberField(max_length=15)
        number = "+2348131234567"
        formatted_number = PhoneNumber.from_string(number).format_as(PhoneNumberFormat.E164)
        value = max_length_field.clean(formatted_number)
        self.assertEqual(value, formatted_number)

    def test_phone_number_max_length_exceeded(self):
        max_length_field = PhoneNumberField(max_length=15)
        number = "+2348131234567890"
        formatted_number = PhoneNumber.from_string(number).format_as(PhoneNumberFormat.E164)
        with self.assertRaises(ValidationError):
            max_length_field.clean(formatted_number)

    def test_phone_number_null(self):
        self.field.null = True
        value = self.field.clean(None)
        self.assertIsNone(value)

    def test_phone_number_default(self):
        default_field = PhoneNumberField(default="+2348131234567")
        value = default_field.clean(default_field.default)
        self.assertEqual(value, default_field.default)