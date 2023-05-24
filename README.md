# Ecommerce Store
### First steps before running is to set the ENV vars:
- SECRET_KEY
- SECURITY_PASSWORD_SALT
- MAIL_USERNAME
- MAIL_PASSWORD

### Stripe:

- STRIPE_SECRET_KEY

## Description:
This ecommerce application's frontend is made with Python Flask.

#### Users
The users are stored in a sqlite database currently (see config.py) but can be changed to s.th. else.
Once a user registers, a confirmation email will be sent to the mailbox.

*The sender is MAIL_USERNAME.
Make sure your given mail-account (MAIL_USERNAME and MAIL_PASSWORD) matches SMTP configuration in config.py. Adjust if necessary.*

#### Products
The products are coming from Stripe and are fetched through Stripe API (Therefore a stripe secret key is needed. You will use your own Stripe products)

#### Admin
A user can be an admin which is set by the User's column 'is_admin'. This flag has to be set manually in the database.
Admin can use the frontend to Add, Modify and Delete Products through Stripe API as well as Modify and Delete users.