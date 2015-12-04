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
    name = Column(String(80), nullable=False)

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
                         ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
