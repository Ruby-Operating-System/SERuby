class SEOS:
    def __init__(self):
        self.users = {}  # List of users
        self.roles = {}  # Roles and their permissions
        self.policies = []  # Access control policies
        self.log = []  # Security events log

    def add_user(self, username, role):
        """Add a new user to the system."""
        if username in self.users:
            raise ValueError("User already exists.")
        self.users[username] = role
        print(f"User {username} added with role {role}.")

    def add_role(self, role, permissions):
        """Define a new role with specific permissions."""
        self.roles[role] = permissions
        print(f"Role {role} defined with permissions: {permissions}")

    def add_policy(self, action, resource, role):
        """Add an access control policy."""
        self.policies.append({"action": action, "resource": resource, "role": role})
        print(f"Policy added: {action} access to {resource} for role {role}.")

    def check_access(self, username, action, resource):
        """Check if a user has access to perform an action on a resource."""
        if username not in self.users:
            self.log_event(username, action, resource, allowed=False)
            return False

        user_role = self.users[username]
        for policy in self.policies:
            if policy["role"] == user_role and policy["action"] == action and policy["resource"] == resource:
                self.log_event(username, action, resource, allowed=True)
                return True

        self.log_event(username, action, resource, allowed=False)
        return False

    def log_event(self, username, action, resource, allowed):
        """Log a security event."""
        event = {
            "username": username,
            "action": action,
            "resource": resource,
            "allowed": allowed,
        }
        self.log.append(event)

    def show_log(self):
        """Display all security events."""
        for event in self.log:
            print(f"User: {event['username']}, Action: {event['action']}, "
                  f"Resource: {event['resource']}, Allowed: {event['allowed']}")


# Example Usage
os_system = SEOS()

# Define roles
os_system.add_role("admin", ["read", "write", "execute"])
os_system.add_role("user", ["read"])

# Add users
os_system.add_user("root", "admin")
os_system.add_user("SEUSER", "user")

# Define policies
os_system.add_policy("read", "/etc/config", "user")
os_system.add_policy("write", "/etc/config", "admin")

# Access control checks
print(os_system.check_access("SEUSER", "read", "/etc/config"))  # True
print(os_system.check_access("SEUSER", "write", "/etc/config"))  # False
print(os_system.check_access("root", "write", "/etc/config"))  # True

# Display logs
os_system.show_log()

#SE designed system
