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
session = DBSession()

# predefined Catalogs
cat1 = Category(name='Soccer')
cat2 = Category(name='Baseball')
cat3 = Category(name='Basketball')
cat4 = Category(name='Frisbee')
cat5 = Category(name='Snowboarding')
cat6 = Category(name='Rock Climbing')
cat7 = Category(name='Foosball')
cat8 = Category(name='Skating')
cat9 = Category(name='Hockey')

session.add(cat1)
session.add(cat2)
session.add(cat3)
session.add(cat4)
session.add(cat5)
session.add(cat6)
session.add(cat7)
session.add(cat8)
session.add(cat9)
session.commit()

# dummy user
user = User(name="aungthiha", email="mr.aungthiha@gmail.com")
session.add(user)
session.commit()

# dummy items
item1 = Item(name="Stick", category_id=9, user_id=1)
item2 = Item(name="Goggles", category_id=5, user_id=1)
item3 = Item(name="Snowboard", category_id=5, user_id=1)
item4 = Item(name="Two shinguards", category_id=1, user_id=1)
item5 = Item(name="Shinguards", category_id=1, user_id=1)
item6 = Item(name="Frisbee", category_id=4, user_id=1)
item7 = Item(name="Bat", category_id=2, user_id=1)
item8 = Item(name="Jersey", category_id=1, user_id=1)
item9 = Item(name="Soccer Cleats", category_id=1, user_id=1)
session.add(item1)
session.add(item2)
session.add(item3)
session.add(item4)
session.add(item5)
session.add(item6)
session.add(item7)
session.add(item8)
session.add(item9)
session.commit()

print 'Categories added!'






