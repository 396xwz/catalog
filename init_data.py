from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base, Categories, Items

import time

engine = create_engine('sqlite:///categoryitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

cat1 = Categories(name = "Football", user_id = '1')
session.add(cat1)
session.commit()

cat2 = Categories(name = "Baseball", user_id = '2')
session.add(cat2)
session.commit()

cat3 = Categories(name = "Soccer", user_id = '3')
session.add(cat3)
session.commit()

catlist = [cat1, cat2, cat3]

for i in range(10):
    item = Items(name = 'Item %s' % str(i),
                description = str(i)*20,
                category = catlist[i%3])
    session.add(item)
    session.commit()

print 'added catagories and items'
