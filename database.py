import os
import sys
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, nullable=False)

    @property
    def serialize(self):
        return {
            'id'    : self.id,
            'name'  : self.name,
        }


class Items(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    description = Column(String(1000))
    create_time = Column(DateTime, default=func.now())
    cata_id = Column(Integer)
    cata_name = Column(String(80))
    category = relationship(Categories)

    __table_args__ = (
        ForeignKeyConstraint(
            ['cata_name', 'cata_id'], 
            ['categories.name', 'categories.id']
        ),
    )
    
    @property
    def serialize(self):
        return {
            'cat_id'    : self.cata_id,
            'description'   : self.description,
            'id'    : self.id,
            'title' : self.name,
        }

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key = True)
    username = Column(String(100), nullable = False)
    email = Column(String(100))
    create_time = Column(DateTime, default=func.now())

engine = create_engine('sqlite:///categoryitem.db')

Base.metadata.create_all(engine)

