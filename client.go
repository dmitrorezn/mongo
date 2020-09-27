package ProjectMongoClient

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"time"

	"github.com/dmitrorezn/classes"
)

type obj map[string]interface{}

func init()  {
	tablesMap := make(map[string]string)
	tablesMap["user"] ="userstable"
	tablesMap["activities"] = "activitiestable"
	tablesMap["orders"] = "orderstable"
	tablesMap["announcements"] = "announcementstable"

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

func (s *DBSession)Update(selector obj, seter obj, updateMany bool, table string) error {
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

func (s *DBSession)Delete(selector obj, deleteMany bool, table string) error {
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

func (s *DBSession) ReadAnnouncements(selector obj) ([]classes.Announcement, error) {
	var result []classes.Announcement
	tablename := "announcementstable"
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Find(selector).All(&result)
	if err != nil ||  len(result) == 0  {
		return nil, fmt.Errorf("no such announcement with this id")
	}
	return result, nil
}

func (s *DBSession) ReadOrder(selector obj) (classes.Order, error) {
	var result classes.Order
	tablename := "orderstable"
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Find(selector).One(&result)
	if err != nil  {
		return classes.Order{}, err
	}
	return result, nil
}

func(s *DBSession) ReadUser(selector obj) (classes.User,error) {
	var result classes.User
	tablename := "userstable"
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Find(selector).One(&result)
	if err != nil  {
		return classes.User{}, err
	}
	return result, nil
}

func (s *DBSession) Read(selector obj) ([]interface{}, error) {
	var result []interface{}
	tablename := "announcementstable"
	workers := s.Session.DB(s.DatabaseName).C(tablename)
	err := workers.Find(selector).One(&result)
	if err != nil  {
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


func (s *DBSession)CheckUserInDB(login, email, password,status string) (classes.User, error) {
	var user classes.User
	hash, err := HashPassword(password)
	if err != nil {

		return classes.User{}, err
	}
	collection := s.Session.DB(s.DatabaseName).C(s.TablesMap["user"])
	err = collection.Find(bson.M{"username": login}).One(&user)
	if err != nil {
		id := primitive.NewObjectIDFromTimestamp(time.Now())
		user := classes.User{
			ID:             id,
			Username:       login,
			Email:          email,
			HashedPassword: hash,
			Status:         status,
		}
		return user, nil
	}
	return classes.User{}, fmt.Errorf("User already exists")
}

func (s *DBSession)CheckUserPassword(login, password string) (classes.User, error) {
	var user classes.User
	collection := s.Session.DB(s.DatabaseName).C(s.TablesMap["user"])
	err := collection.Find(bson.M{"username": login}).One(&user)
	if err != nil {
		return classes.User{}, err
	}
	if CheckPasswordHash(password, user.HashedPassword) != true {
		return classes.User{}, fmt.Errorf("Error: Wrong password or login for this account!")
	}
	return user, nil
}

