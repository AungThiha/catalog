# Configuration
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

__author__ = 'aungthiha'

Base = declarative_base()


class User(Base):

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }


class Category(Base):

    __tablename__ = 'category'

    id = Column(Integer,
                primary_key=True)
    name = Column(String(80), nullable=False,
                  unique=True)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
        }


class Item(Base):

    __tablename__ = 'item'

    id = Column(Integer,
                primary_key=True)
    name = Column(String(80),
                  nullable=False)
    photo = Column(String)
    description = Column(String(250))
    category_id = Column(Integer,
                         ForeignKey('category.id'),
                         nullable=False)
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'),
                     nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category_id': self.category_id
        }


engine = create_engine('postgres://duwwgnpwekloeh:oLujnvRK3_6zwO5wzYCRuVscoq@ec2-54-83-198-111.compute-1.amazonaws.com:5432/d1qachm673fvj7')

Base.metadata.create_all(engine)
