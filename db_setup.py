from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(
    TimedJSONWebSignatureSerializer as
    Serializer, BadSignature, SignatureExpired)
import datetime

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in range(32))


def _get_date():
    return datetime.datetime.now()

# Website Users Table


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    email = Column(String(250), nullable=False)
    role = Column(String(250))
    password_hash = Column(String(64))
    displayName = Column(String(32))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self):
        s = Serializer(secret_key)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        return {'username': self.username,
                'Name': self.displayName, }

# Character Information


class Character(Base):
    __tablename__ = 'character'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    race = Column(String(250))
    gender = Column(String(250))
    image = Column(String(250))
    image_url = Column(String(250))
    faction = Column(String(250))
    biography = Column(String(250))
    owner_name = Column(String(250), ForeignKey('user.username'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship("User", foreign_keys=[user_id])
    owner = relationship("User", foreign_keys=[owner_name])

    @property
    def serialize(self):
        return {'Name': self.name,
                'race': self.race,
                'gender': self.gender,
                'image_url': self.image_url,
                'faction': self.faction,
                'biography': self.biography,
                'player': self.owner_name}

# Blog Entry


class BlogEntry(Base):
    __tablename__ = 'entry'
    id = Column(Integer, primary_key=True)
    title = Column(String(250), nullable=False)
    entry = Column(String(1000000), nullable=False)
    tags = Column(String(250))
    author = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship("User", foreign_keys=[user_id])

# End Code Stuff


engine = create_engine('sqlite:///database.db')
Base.metadata.create_all(engine)
