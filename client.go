package ProjectMongoClient

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"time"
)

type obj map[string]interface{}

type User struct {
	ID             primitive.ObjectID `json:"id" bson:"_id"`
	IDString       string             `json:"idstr" bson:"_idstr"`
	Username       string             `json:"username" bson:"username"`
	Email          string             `json:"email" bson:"email"`
	HashedPassword string             `json:"password" bson:"password"`
	Status         string             `json:"status" bson:"status"`
	//Status 	for              Admin 	 -> admin
	//Status 	for      		 User	 -> user
	//Status    for Announcement Author  -> author
}

type DBSession struct {
	Session      *mgo.Session
	DatabaseName string
	TablesMap    map[string]string
}

func NewSession(dbname string, tablesmap map[string]string) (*DBSession, error) {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		return nil, err
	}
	dbsession := &DBSession{
		Session:      session,
		DatabaseName: dbname,
		TablesMap:    tablesmap,
	}
	return dbsession, nil
}

func (s *DBSession) Close() {
	s.Session.Close()
}

func (s *DBSession) Update(selector obj, seter bson.M, updateMany bool, table string) error {
	tablename, ok := s.TablesMap[table]
	if !ok {
		return fmt.Errorf("no such table in db")
	}
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	if updateMany {
		_, err := workers.UpdateAll(selector, bson.M{"$set": seter})
		if err != nil {
			return err
		}
	} else {
		err := workers.Update(selector, bson.M{"$set": seter})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *DBSession) Delete(selector obj, deleteMany bool, table string) error {
	tablename, ok := s.TablesMap[table]
	if !ok {
		return fmt.Errorf("no such table in db")
	}
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	if deleteMany {
		_, err := workers.RemoveAll(selector)
		if err != nil {
			return err
		}
	} else {
		err := workers.Remove(selector)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *DBSession) Insert(data interface{}, table string) error {
	tablename, ok := s.TablesMap[table]
	if !ok {
		return fmt.Errorf("no such table in db")
	}
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Insert(data)
	if err != nil {
		return err
	}
	return nil
}

func (s *DBSession) Read(selector obj, table string) ([]interface{}, error) {
	var result []interface{}
	tablename, ok := s.TablesMap[table]
	if !ok {
		return nil, fmt.Errorf("no such table in db")
	}
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Find(selector).All(&result)
	if len(result) == 0 {
		return nil, err
	}
	return result, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}


func (s *DBSession)CheckUserInDB(login, email, password string) (User, error) {
	var user User
	hash, err := HashPassword(password)
	if err != nil {
		fmt.Println(err.Error())
		return User{}, err
	}

	collection := s.Session.DB(s.DatabaseName).C(s.TablesMap["user"])
	err = collection.Find(bson.M{"username": login}).One(&user)
	if err != nil {
		id := primitive.NewObjectIDFromTimestamp(time.Now())
		user := User{
			ID:             id,
			IDString:       id.String(),
			Username:       login,
			Email:          email,
			HashedPassword: hash,
		}
		return user, nil
	}
	return User{}, fmt.Errorf("User already exists")
}

func (s *DBSession)CheckUserPassword(login, password string) (User, error) {
	var user User
	collection := s.Session.DB(s.DatabaseName).C(s.TablesMap["user"])
	err := collection.Find(bson.M{"username": login}).One(&user)
	if err != nil {
		return User{}, err
	}
	if CheckPasswordHash(password, user.HashedPassword) != true {
		return User{}, fmt.Errorf("Error: Wrong password or login for this account!")
	}
	return user, nil
}