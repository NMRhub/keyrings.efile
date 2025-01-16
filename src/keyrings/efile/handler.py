import getpass
import keyring

from keyrings.efile import kef_logger


class FallbackPasswordHandler:
    def __init__(self, service_name, username):
        """
        Initialize with the service and username for keyring lookup.
        :param service_name: The name of the service to retrieve the password for.
        :param username: The username associated with the service.
        """
        self.service_name = service_name
        self.username = username
        self.password = None
        self.password_was_prompted = False

    def __enter__(self):
        """
        Context manager entry point.
        Retrieves the password from the keyring or prompts the user.
        :return: The password as a string.
        """
        self.password = keyring.get_password(self.service_name, self.username)
        if not self.password:
            self.password = getpass.getpass(f"Password for {self.service_name} {self.username}: ")
            self.password_was_prompted = True
        return self.password

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Context manager exit point.
        Stores the password in the keyring if it was prompted and no exception occurred.
        """
        if self.password_was_prompted and exc_type is None:
            keyring.set_password(self.service_name, self.username, self.password)

    def delete_password(self):
        """
        Deletes the password for the service and username from the keyring.
        """
        keyring.delete_password(self.service_name, self.username)

