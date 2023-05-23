from flask_mail import Message


def send_email(to, subject, template):
    from main import application, mail
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=application.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)