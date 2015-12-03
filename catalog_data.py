from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base

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
cat1 = Catalog(name='Soccer')
cat2 = Catalog(name='Basketball')
cat3 = Catalog(name='Frisbee')
cat4 = Catalog(name='Snowboarding')
cat5 = Catalog(name='Rock Climbing')
cat6 = Catalog(name='Foosball')
cat7 = Catalog(name='Skating')
cat8 = Catalog(name='Hockey')

session.add(cat1)
session.add(cat2)
session.add(cat3)
session.add(cat4)
session.add(cat5)
session.add(cat6)
session.add(cat7)
session.add(cat8)

session.commit()

print 'Catalogs added!'






