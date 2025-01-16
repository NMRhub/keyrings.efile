import logging
from unittest import TestCase

from keyrings.efile import kef_logger, FallbackPasswordHandler


class TestFallbackPasswordHandler(TestCase):

    def setUp(self):
        super().setUp()
        logging.basicConfig()
        kef_logger.setLevel(logging.DEBUG)

    def test_store(self):
        try:
            with FallbackPasswordHandler(service_name="example_service", username="user@example.com") as password:
                print(f"Using password: {'*' * len(password)}")  # Mask the password for display
                # Perform operations that require the password
                pass
        except Exception as e:
            print(f"An error occurred: {e}")

    def test_delete(self):
        # Example of deleting the password
        handler = FallbackPasswordHandler(service_name="example_service", username="user@example.com")
        handler.delete_password()
