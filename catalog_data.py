from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

__author__ = 'aungthiha'

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
db = DBSession()

# predefined Catalogs
categories = ['Soccer', 'Baseball',
              'Basketball', 'Frisbee',
              'Snowboarding', 'Rock Climbing',
              'Foosball', 'Skating', ' Hockey']

for c in categories:
    category = Category(name=c)
    db.add(category)

db.commit()

# dummy user
user = User(name="aungthiha", email="mr.aungthiha@gmail.com")
db.add(user)
db.commit()


# dummy items
def add_item(name, category_id):
    add_item_with_user(name, category_id, 1)


def add_item_with_user(name, category_id, user_id):
    item = Item(name=name, category_id=category_id, user_id=user_id)
    db.add(item)

add_item("Stick", 9)
add_item("Goggles", 5)
add_item("Snowboard", 5)
add_item("Two shinguards", 1)
add_item("Shinguards", 1)
add_item("Frisbee", 4)
add_item("Bat", 2)
add_item("Jersey", 1)
add_item("Soccer Cleats", 1)

db.commit()

print 'Categories added!'
