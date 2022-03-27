package routes

import (
	"StoreServer/internal/config"
	"StoreServer/internal/service"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"html/template"
	"io"
	"net/http"
)

type Handler struct {
	Services *service.Service
	cfg      *config.Config
}

const startCategory = "65"

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

	//router.Use(Middleware(cfg))
	// Init router
	router.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})
	router.GET("/categories/:id", h.ProductsByCategories)
	router.GET("/categories/", h.GetStartCategories)

	return router
}

func (h *Handler) ProductsByCategories(c echo.Context) error {
	id := c.Param("id")
	resp, err := h.Services.DB.GetProductsById(id)
	if err != nil {
		return c.JSON(500, err.Error())
	}

	return c.Render(200, "index.html", map[string]interface{}{
		"name":            resp.Name,
		"childCategories": resp.SubCategories,
		"products":        resp.Products,
	})
}

func (h *Handler) GetStartCategories(c echo.Context) error {
	resp, err := h.Services.DB.GetProductsById(startCategory)
	if err != nil {
		return c.JSON(500, err.Error())
	}

	return c.Render(200, "index.html", map[string]interface{}{
		"name":            resp.Name,
		"childCategories": resp.SubCategories,
		"products":        resp.Products,
	})
}

type AuthClaims struct {
	Id     string `json:"id"`
	Login  string `json:"login"`
	RoleID int    `json:"role_id"`
	jwt.StandardClaims
}

func Middleware(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			header := c.Request().Header.Get("Authorization")
			if header == "" {
				return c.JSON(401, "Unauthorized")
			}

			token, err := jwt.ParseWithClaims(
				header,
				&AuthClaims{},
				func(token *jwt.Token) (interface{}, error) {
					return cfg.Secretkey, nil
				},
			)

			if err != nil {
				return c.JSON(401, "Unauthorized")
			}

			claims, ok := token.Claims.(*AuthClaims)
			if !ok {
				return c.JSON(401, "Unauthorized")
			}

			if claims.Login != "" && claims.Id != "" && claims.RoleID != 0 {
				return next(c)
			}

			return c.JSON(401, "Unauthorized")
		}
	}
}
