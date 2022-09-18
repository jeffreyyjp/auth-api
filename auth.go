package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserSet map[User]struct{}

var userSet UserSet

func (u UserSet) add(user User) bool {
	for v := range u {
		if v.Username == user.Username {
			return false
		}
	}
	u[user] = struct{}{}
	return true
}

func (u UserSet) remove(user User) bool {
	if u.has(user.Username) {
		delete(u, user)
		return true
	}
	return false
}

func (u UserSet) has(username string) bool {
	for user := range u {
		if user.Username == username {
			return true
		}
	}
	return false
}

func (u UserSet) HandleUsers(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST":
		var user User
		err := json.NewDecoder(req.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if u.has(user.Username) {
			http.Error(w, "User already existed", http.StatusBadRequest)
			return
		}
		if !u.add(user) {
			http.Error(w, "username is already existed", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "user: %s has created successfully\n", user.Username)
	case "DELETE":
		var user User
		err := json.NewDecoder(req.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !u.remove(user) {
			http.Error(w, "User doesn't exist", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "User %s has been deleted\n", user.Username)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't support\n", req.Method)
	}
}

type Role struct {
	Name string
}

type RoleSet map[Role]struct{}

var roleSet RoleSet

func (r RoleSet) add(role Role) {
	r[role] = struct{}{}
}

func (r RoleSet) remove(role Role) {
	delete(r, role)
}

func (r RoleSet) has(roleName string) bool {
	for role := range r {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

func (r RoleSet) HandleRoles(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST":
		var role Role
		err := json.NewDecoder(req.Body).Decode(&role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.has(role.Name) {
			http.Error(w, "User already existed", http.StatusBadRequest)
			return
		}
		r.add(role)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Role %s has been created successfully\n", role.Name)
	case "DELETE":
		var role Role
		err := json.NewDecoder(req.Body).Decode(&role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !r.has(role.Name) {
			http.Error(w, "Role doesn't exist", http.StatusBadRequest)
			return
		}
		r.remove(role)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Role %s has been deleted successfully\n", role.Name)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't support\n", req.Method)
	}
}

type roleWithUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type UserEntity map[string][]string

var ue UserEntity

func (ue UserEntity) hasRoleAssignedToUser(ru roleWithUser) bool {
	roles, ok := ue[ru.Username]
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == ru.Role {
			return true
		}
	}
	return false
}

func (ue UserEntity) addRoleToUserHelper(ru roleWithUser) {
	if ue.hasRoleAssignedToUser(ru) {
		return
	}
	ue[ru.Username] = append(ue[ru.Username], ru.Role)
}

func (ue UserEntity) addRoleToUser(w http.ResponseWriter, req *http.Request) {
	if req.Method != "PUT" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't support\n", req.Method)
		return
	}
	var ru roleWithUser
	err := json.NewDecoder(req.Body).Decode(&ru)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !userSet.has(ru.Username) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "User %s doesn't exist, please create user first\n", ru.Username)
		return
	}
	if !roleSet.has(ru.Role) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Role %s doesn't exist, please create role first\n", ru.Role)
		return
	}
	ue.addRoleToUserHelper(ru)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "add role: %s to user: %s succeed\n", ru.Role, ru.Username)

}

type Token struct {
	id         string
	createTime time.Time
	isValid    bool
}

func (t *Token) isExpired() bool {
	return time.Since(t.createTime) > time.Duration(2*60*60)
}

type tokenWithUser map[Token]string

var tu tokenWithUser

func authenticate(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't allowed\n", req.Method)
		return
	}
	var user User
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for u := range userSet {
		if u.Username == user.Username && u.Password == user.Password {
			baseString := user.Username + time.Now().GoString()
			token := Token{id: base64.StdEncoding.EncodeToString([]byte(baseString)), createTime: time.Now(), isValid: true}
			tu[token] = user.Username
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			resp := make(map[string]string)
			resp["token"] = token.id
			jsonResp, err := json.Marshal(resp)
			if err != nil {
				http.Error(w, "json marshal error", http.StatusBadRequest)
				return
			}
			w.Write(jsonResp)
			return
		}
	}
	http.Error(w, "login failed", http.StatusUnauthorized)
}

func invalidate(w http.ResponseWriter, req *http.Request) {
	if req.Method != "PATCH" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't supported\n", req.Method)
		return
	}
	type requestToken struct {
		Token string `json:"token"`
	}
	var rt requestToken
	err := json.NewDecoder(req.Body).Decode(&rt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for t := range tu {
		if t.id == rt.Token {
			t.isValid = false
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "provided token is invalid\n")
}

func checkRole(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't supported\n", req.Method)
		return
	}
	authToken := req.Header.Get("Authorization")
	if !strings.HasPrefix(authToken, "Basic") {
		http.Error(w, "auth token is not in http request token or not basic type", http.StatusBadRequest)
		return
	}
	authToken = strings.TrimPrefix(authToken, "Basic ")
	role := req.URL.Query().Get("role")
	for t := range tu {
		if t.id == authToken {
			if !t.isValid || t.isExpired() {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "token is invalid or expired\n")
				return
			}
			w.WriteHeader(http.StatusOK)
			ru := roleWithUser{tu[t], role}
			if ue.hasRoleAssignedToUser(ru) {
				fmt.Fprintf(w, "the user: %s belongs to role: %s\n", tu[t], role)
			} else {
				fmt.Fprintf(w, "the user: %s doesn't belong to role: %s\n", tu[t], role)
			}
		}
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "bad token\n")
}

func getAllRoles(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "%s method doesn't supported\n", req.Method)
		return
	}
	authToken := req.Header.Get("Authorization")
	if !strings.HasPrefix(authToken, "Basic") {
		http.Error(w, "auth token is not in http request token or not basic type", http.StatusBadRequest)
		return
	}
	authToken = strings.TrimPrefix(authToken, "Basic ")
	for t := range tu {
		if t.id == authToken {
			if !t.isValid || t.isExpired() {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "token is invalid or expired\n")
				return
			}
			jsonResp, err := json.Marshal(ue[tu[t]])
			if err != nil {
				http.Error(w, "json marshal error", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonResp)
			return
		}
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "bad token\n")
}

func main() {
	userSet = UserSet{}
	roleSet = RoleSet{}
	ue = UserEntity{}
	tu = tokenWithUser{}
	http.HandleFunc("/users", userSet.HandleUsers)
	http.HandleFunc("/roles", roleSet.HandleRoles)
	http.HandleFunc("/add_role_to_user", ue.addRoleToUser)
	http.HandleFunc("/authenticate", authenticate)
	http.HandleFunc("/invalidate", invalidate)
	http.HandleFunc("/check_role", checkRole)
	http.HandleFunc("/all_roles", getAllRoles)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}
