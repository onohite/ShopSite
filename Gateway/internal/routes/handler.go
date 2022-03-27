package routes

import (
	"Gateway/internal/config"
	"Gateway/internal/service"
	"Gateway/internal/service/db"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
)

const authURL = "http://localhost:8081/Auth"

type Handler struct {
	Services *service.Service
	cfg      *config.Config
}

func NewHandler(service *service.Service, cfg *config.Config) *Handler {
	return &Handler{service, cfg}
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func (h *Handler) Init(cfg *config.Config) *echo.Echo {
	// Init echo handler
	router := echo.New()

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("./internal/views/*.html")),
	}
	router.Renderer = renderer

	router.Static("static", "./internal/views")

	// Init middleware
	router.Use(
		middleware.LoggerWithConfig(middleware.LoggerConfig{
			Format: "[${time_rfc3339}] ${status} ${method} ${path} (${remote_ip}) ${latency_human}, bytes_in=${bytes_in}, bytes_out=${bytes_out}\n",
			Output: router.Logger.Output()}),
		middleware.Recover())

	// Init log level
	router.Debug = cfg.ServerMode != config.Dev

	// Init router
	router.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	//router.Use(ApiGateway)

	router.GET("/auth", h.AuthForm)
	router.GET("/register", h.RegisterForm)
	router.POST("/api/user/login", h.UserLogin)
	router.POST("/api/user/signup", h.UserSignup)

	return router
}

func (h *Handler) AuthForm(c echo.Context) error {

	return c.Render(200, "login.html", nil)
}

func (h *Handler) RegisterForm(c echo.Context) error {

	return c.Render(200, "register.html", nil)
}

func ApiGateway(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		url := c.Request().RequestURI
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.Redirect(307, authURL)
		}

		if strings.Contains(url, "admin") {

			return c.Redirect(307, "http://localhost:5000"+url)
		}

		if strings.Contains(url, "categories") {

			return c.Redirect(307, "http://localhost:8080"+url)
		}

		return c.Redirect(307, authURL)
	}
}

func (h *Handler) UserSignup(c echo.Context) error {
	authType := c.QueryParam("type")
	if authType == "" {
		authType = "2"
	}
	c.Response().Header().Set("Content-Type", "application/json")
	login := c.FormValue("Login")
	if login == "" {
		return c.JSON(401, "bad login")
	}

	password := c.FormValue("Password")
	if password == "" {
		return c.JSON(401, "bad password")
	}

	email := c.FormValue("Email")
	if email == "" {
		return c.JSON(401, "bad email")
	}

	user := db.User{Login: login, Password: getHash([]byte(password)), Email: email}

	id, err := h.Services.DB.AddUser(user)
	if err != nil {
		log.Println(err)
		return c.JSON(500, err.Error())
	}

	err = h.Services.DB.SetRoleForUser(id, authType)
	if err != nil {
		log.Println(err)
		return c.JSON(500, err.Error())
	}
	return c.Redirect(302, "http://localhost:8081/auth")
}

func (h *Handler) UserLogin(c echo.Context) error {
	c.Response().Header().Set("Content-Type", "application/json")
	var dbUser *db.User
	login := c.FormValue("Login")
	password := c.FormValue("Password")

	dbUser, err := h.Services.DB.GetUser(login)
	if err != nil {
		log.Println(err)
		return c.Redirect(302, "http://localhost:8081/auth")
	}
	userPass := []byte(password)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		return c.Redirect(302, "http://localhost:8081/auth")
	}

	roleId, err := h.Services.DB.GetRoleByUserID(dbUser.Id)
	if err != nil {
		log.Println(err)
		return c.Redirect(302, "http://localhost:8081/auth")
	}

	jwtToken, err := GenerateJWT(h.cfg.Secretkey, dbUser.Id, roleId, dbUser.Login)
	if err != nil {
		return c.Redirect(302, "http://localhost:8081/auth")
	}

	//TODO store token in cookie and read
	return c.JSONBlob(http.StatusOK, []byte(`{"token":"`+jwtToken+`"}`))
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

type AuthClaims struct {
	Id     int    `json:"id"`
	Login  string `json:"login"`
	RoleID int    `json:"role_id"`
	jwt.StandardClaims
}

func GenerateJWT(secret []byte, id int, role int, login string) (string, error) {
	claims := AuthClaims{id, login, role, jwt.StandardClaims{}}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}
