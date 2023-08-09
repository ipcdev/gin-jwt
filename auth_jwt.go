package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
//
// 使用 map[string]interface{} 进行 JSON 解码的 MapClaims 类型
// 如果您不提供，这是默认的声明类型
type MapClaims map[string]interface{}

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
//
// GinJWTMiddleware 提供了 Json-Web-Token 认证实现。
// 失败时，将返回 401 HTTP 响应。
// 成功后，将调用包装的中间件，并以 c.Get("userID").(string) 形式提供 userID。
// 用户可以通过向 LoginHandler 发送 json 请求来获取令牌。 然后需要在 Authentication header 中传递令牌。
// 示例：Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware struct {
	// Realm name to display to the user. Required.
	// 显示给用户的 Realm 名称。 必需的。
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, default is HS256.
	// 签名算法 - 可能的值为 HS256、HS384、HS512、RS256、RS384 或 RS512
	// 可选，默认为 HS256。
	SigningAlgorithm string

	// Secret key used for signing. Required.
	// 用于签名的密钥。 必需的。
	Key []byte

	// Callback to retrieve key used for signing. Setting KeyFunc will bypass
	// all other key settings
	// 回调以检索用于签名的密钥。 设置 KeyFunc 将绕过所有其他 key 设置
	KeyFunc func(token *jwt.Token) (interface{}, error)

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	// jwt 令牌的有效持续时间。 可选，默认为一小时。
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	//
	// 该字段允许客户端刷新其令牌，直到 MaxRefresh 过去。
	// 请注意，客户端可以在 MaxRefresh 的最后时刻刷新其令牌。
	// 这意味着令牌的最大有效时间为 TokenTime + MaxRefresh。
	// 可选，默认为 0 表示不可刷新。
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on login info.
	// Must return user data as user identifier, it will be stored in Claim Array. Required.
	// Check error (e) to determine the appropriate error message.
	//
	// 应根据登录信息执行 用户身份验证 的回调函数。
	// 必须返回用户数据作为用户标识符，它将存储在 Claim Array 中。 必需的。
	// 检查错误 (e) 以确定适当的错误消息。
	Authenticator func(c *gin.Context) (interface{}, error)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	//
	// 回调函数，经过身份验证的用户授权的应该执行。 仅在身份验证成功后调用。 成功时必须返回 true，失败时返回 false。
	// 可选，默认成功。
	Authorizator func(data interface{}, c *gin.Context) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	//
	// 登录时调用的回调函数。
	// 使用此函数可以向 webtoken 添加额外的有效负载数据。
	// 然后，数据在通过 c.Get("JWT_PAYLOAD") 请求期间可用。
	// 请注意，有效负载未加密。
	// jwt.io 上提到的属性不能用作 map 的键。
	// 可选，默认情况下不会设置任何附加数据。
	PayloadFunc func(data interface{}) MapClaims

	// User can define own Unauthorized func.
	// 用户可以定义自己的未授权 func。
	Unauthorized func(c *gin.Context, code int, message string)

	// User can define own LoginResponse func.
	LoginResponse func(c *gin.Context, code int, message string, time time.Time)

	// User can define own LogoutResponse func.
	LogoutResponse func(c *gin.Context, code int)

	// User can define own RefreshResponse func.
	RefreshResponse func(c *gin.Context, code int, message string, time time.Time)

	// Set the identity handler function
	// 设置身份处理函数
	IdentityHandler func(*gin.Context) interface{}

	// Set the identity key
	// 设置身份密钥
	IdentityKey string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	//
	// TokenLookup 是一个 "<source>:<name>" 形式的字符串，用于从请求中提取 token。
	// 可选的。 默认值 "header:Authorization"
	// 可能的值：
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	//
	// <source>：从哪个位置查询，可取值（"header"、"query"、"cookie"、"param"、"form"）
	// <name>：查询哪个值
	// 例如："header:Authorization"，从 HTTP 请求头，Authorization 头中提取 token
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	// TokenHeadName 是 header 中的字符串。 默认值为 "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value.
	// This is useful for testing or if your server uses a different time zone than your tokens.
	// TimeFunc 提供当前时间。 您可以覆盖它以使用其他时间值。
	// 这对于测试 或 您的服务器使用与令牌不同的时区时非常有用。
	TimeFunc func() time.Time

	// HTTP Status messages for when something in the JWT middleware fails.
	// Check error (e) to determine the appropriate error message.
	// JWT 中间件中的某些内容发生故障时的 HTTP 状态消息。
	// 检查错误 (e) 以确定适当的错误消息。
	HTTPStatusMessageFunc func(e error, c *gin.Context) string

	// Private key file for asymmetric algorithms
	// 非对称算法的私钥文件
	PrivKeyFile string

	// Private Key bytes for asymmetric algorithms
	//
	// Note: PrivKeyFile takes precedence over PrivKeyBytes if both are set
	//
	// 非对称算法的私钥字节
	//
	// 注意：如果两者都设置了，PrivKeyFile 优先于 PrivKeyBytes
	PrivKeyBytes []byte

	// Public key file for asymmetric algorithms
	// 非对称算法的公钥文件
	PubKeyFile string

	// Private key passphrase
	// 私钥密码
	PrivateKeyPassphrase string

	// Public key bytes for asymmetric algorithms.
	//
	// Note: PubKeyFile takes precedence over PubKeyBytes if both are set
	//
	// 非对称算法的公钥字节。
	//
	// 注意：如果两者都设置了，PubKeyFile 优先于 PubKeyBytes
	PubKeyBytes []byte

	// Private key
	// 私钥
	privKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	// Optionally return the token as a cookie
	// 可以选择将 token 作为 cookie 返回
	SendCookie bool

	// Duration that a cookie is valid. Optional, by default equals to Timeout value.
	// cookie 的有效持续时间。 可选，默认等于超时值。
	CookieMaxAge time.Duration

	// Allow insecure cookies for development over http
	// 允许通过 http 进行不安全的 cookie 开发
	SecureCookie bool

	// Allow cookies to be accessed client side for development
	// 允许客户端访问cookie以进行开发
	CookieHTTPOnly bool

	// Allow cookie domain change for development
	// 允许更改 cookie 域以进行开发
	CookieDomain string

	// SendAuthorization allow return authorization header for every request
	// SendAuthorization 允许为每个请求返回 authorization header
	// true：从 gin 上下文中查找 "JWT_TOKEN"，如果查找到，则在头部设置 c.Header("Authorization", mw.TokenHeadName+" "+ ${JWT_TOKEN})
	SendAuthorization bool

	// Disable abort() of context.
	DisabledAbort bool

	// CookieName allow cookie name change for development
	// CookieName 允许更改 cookie 名称以供开发
	CookieName string

	// CookieSameSite allow use http.SameSite cookie param
	// CookieSameSite 允许使用 http.SameSite cookie 参数
	CookieSameSite http.SameSite

	// ParseOptions allow to modify jwt's parser methods
	// ParseOptions 允许修改 jwt 的解析器方法
	ParseOptions []jwt.ParserOption
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired") // in practice, this is generated from the jwt library not by us

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"
)

// New for check error with GinJWTMiddleware
func New(m *GinJWTMiddleware) (*GinJWTMiddleware, error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}

	return m, nil
}

// MiddlewareInit initialize jwt configs.
// 初始化 jwt 配置
func (mw *GinJWTMiddleware) MiddlewareInit() error {
	// TokenLookup 用于从请求中提取 token，默认值 "header:Authorization"
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	// 签名算法，默认值 HS256
	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	// jwt token 有效持续时间，默认 一小时
	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	// 时间函数，默认当前时间
	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	// header 中的字符串，默认值 "Bearer"
	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	// 回调函数，身份认证成功后调用，默认返回 true
	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c *gin.Context) bool {
			return true
		}
	}

	// 回调函数，授权失败
	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	// 回调函数，登录响应
	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(http.StatusOK, gin.H{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	// 回调函数，退出响应
	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(c *gin.Context, code int) {
			c.JSON(http.StatusOK, gin.H{
				"code": http.StatusOK,
			})
		}
	}

	// 回调函数，刷新响应
	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(http.StatusOK, gin.H{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	// 身份秘钥，默认 "identity"
	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	// 身份处理回调函数
	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(c *gin.Context) interface{} {
			claims := ExtractClaims(c)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, c *gin.Context) string {
			return e.Error()
		}
	}

	// 显示给用户的 Realm 名称，默认 "gin jwt"
	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}

	// Cookie 的有效持续时间，默认等于超时值。
	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	// Cookie 名称，默认值 jwt
	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	// bypass other key settings if KeyFunc is set
	// 如果设置了 KeyFunc，则放行其他 key 设置
	if mw.KeyFunc != nil {
		return nil
	}

	// 判断是否使用公钥算法（"RS256", "RS512", "RS384"）
	if mw.usingPublicKeyAlgo() {
		// 获取 公钥、私钥
		return mw.readKeys()
	}

	// HS256、HS384、HS512
	// 判断签名的秘钥是否为 nil，必须
	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

func (mw *GinJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

func (mw *GinJWTMiddleware) readKeys() error {
	// 获取私钥
	err := mw.privateKey()
	if err != nil {
		return err
	}

	// 获取公钥
	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

// 解析 私钥文件 或者 私钥字节，获取私钥
func (mw *GinJWTMiddleware) privateKey() error {
	var keyData []byte

	if mw.PrivKeyFile == "" {
		// 如果 非对称算法的私钥文件 为 ""，则使用 非对称算法的私钥字节
		keyData = mw.PrivKeyBytes
	} else {
		// 如果 非对称算法的私钥文件 不为空，则读取私钥文件内容
		filecontent, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}

	// 如果私钥密码不为空，则使用密码解析私钥文件内容，获取私钥
	if mw.PrivateKeyPassphrase != "" {
		//nolint:staticcheck
		key, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyData, mw.PrivateKeyPassphrase)
		if err != nil {
			return ErrInvalidPrivKey
		}
		mw.privKey = key
		return nil
	}

	// 直接解析私钥文件 或者 私钥字节，获取私钥
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

// 解析 公钥文件 或者 公钥字节，获取公钥
func (mw *GinJWTMiddleware) publicKey() error {
	var keyData []byte

	if mw.PubKeyFile == "" {
		// 如果 非对称算法的公钥文件 为 ""，则使用 非对称算法的公钥字节
		keyData = mw.PubKeyBytes
	} else {
		// 如果 非对称算法的公钥文件 不为空，则读取公钥文件内容
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}

	// 直接解析公钥文件 或者 公钥字节，获取公钥
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

// MiddlewareFunc makes GinJWTMiddleware implement the Middleware interface.
// MiddlewareFunc 使 GinJWTMiddleware 实现 Middleware 接口。
func (mw *GinJWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
	}
}

func (mw *GinJWTMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// exp 过期时间，类型断言
	switch v := claims["exp"].(type) {
	case nil:
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, c))
		return
	case float64:
		// 过期时间 < 当前时间
		if int64(v) < mw.TimeFunc().Unix() {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
			return
		}
	case json.Number:
		// json.Number 转成 Int64
		n, err := v.Int64()
		if err != nil {
			mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, c))
			return
		}

		// 过期时间 < 当前时间
		if n < mw.TimeFunc().Unix() {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
			return
		}
	default:
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, c))
		return
	}

	// claims 保存到 gin 上下文 "JWT_PAYLOAD"
	c.Set("JWT_PAYLOAD", claims)

	identity := mw.IdentityHandler(c)

	if identity != nil {
		// identity 保存到 gin 上下文
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	c.Next()
}

// GetClaimsFromJWT get claims from JWT token
// GetClaimsFromJWT 从 JWT token 获取 claims
func (mw *GinJWTMiddleware) GetClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	// 解析 token
	token, err := mw.ParseToken(c)
	if err != nil {
		return nil, err
	}

	// 是否为每个请求设置 Authorization: Bearer ${JWT_TOKEN}
	if mw.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			c.Header("Authorization", mw.TokenHeadName+" "+v.(string))
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

// ParseToken parse jwt token from gin context
// 从 gin 上下文中得出 jwt token 字符串，并使用 jwt 包进行解析
func (mw *GinJWTMiddleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	// 使用 "," 切分 TokenLookup 字段
	methods := strings.Split(mw.TokenLookup, ",")

	// 遍历 methods
	for _, method := range methods {
		// 如果 token 的长度 大于 0，说明已经解析到 token，停止遍历
		if len(token) > 0 {
			break
		}

		// method 去除空格，使用 ":" 切分
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0]) // key（"header"、"query"、"cookie"、"param"、"form"）
		v := strings.TrimSpace(parts[1])

		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "query":
			token, err = mw.jwtFromQuery(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		case "param":
			token, err = mw.jwtFromParam(c, v)
		case "form":
			token, err = mw.jwtFromForm(c, v)
		}
	}

	if err != nil {
		// 解析 token 出错
		return nil, err
	}

	// 使用自定义 KeyFunc 回调函数，解析 token
	// 回调函数要返回用于加密的 秘钥
	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	// 默认方式解析 token
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// 加密算法校验
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			// token 的加密算法，与配置的加密算法不一致
			return nil, ErrInvalidSigningAlgorithm
		}

		// 如果使用公钥算法（"RS256", "RS512", "RS384"），返回公钥
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// 使用（HS256、HS384、HS512），保存 token 到上下文 "JWT_TOKEN"，然后返回用于签名的秘钥 Key
		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	}, mw.ParseOptions...)
}

// 从 HTTP 请求头中解析 token
func (mw *GinJWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	// 如果提取为空，返回 ErrEmptyAuthHeader 错误
	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	// 使用 空格 进行切分，将 authHeader 切分成两段
	// 合法条件：
	//      1、切分后数量为 2 个；
	//      2、第一个为 TokenHeadName
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	// 返回 token
	return parts[1], nil
}

// 从 Query 中解析 token
func (mw *GinJWTMiddleware) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

// 从 Cookie 中解析 token
func (mw *GinJWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

// 从 Param 中解析 token
func (mw *GinJWTMiddleware) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// 从 Form 表单中解析 token
func (mw *GinJWTMiddleware) jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
//
// 客户端可以使用 LoginHandler 来获取 jwt 令牌。
// Payload 需要为 {"username": "USERNAME","password": "PASSWORD"} 形式的 json。
// 回复的格式为 {"token": "TOKEN"}。
func (mw *GinJWTMiddleware) LoginHandler(c *gin.Context) {
	if mw.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		return
	}

	data, err := mw.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm)) // 获取签名方法，并创建 token
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.Timeout) // Token 过期时间：当前时间 + 超时时间
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix() // Token 签发时间

	// 签发 token
	tokenString, err := mw.signedString(token)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}

	// set cookie
	//可以选择将 token 作为 cookie 返回
	if mw.SendCookie {
		// cookie 有效期
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())

		// ？？
		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		// 设置 Cookie
		c.SetCookie(
			mw.CookieName,
			tokenString,
			maxage,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}

	// 登录成功响应
	mw.LoginResponse(c, http.StatusOK, tokenString, expire)
}

// 对 token 进行签发，返回 string
func (mw *GinJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error

	if mw.usingPublicKeyAlgo() {
		// 使用私钥签发 token （"RS256", "RS512", "RS384"）
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		// 使用秘钥签发 token
		tokenString, err = token.SignedString(mw.Key)
	}

	return tokenString, err
}

// LogoutHandler can be used by clients to remove the jwt cookie (if set)
// 客户端可以使用 LogoutHandler 删除 jwt cookie（如果设置）
func (mw *GinJWTMiddleware) LogoutHandler(c *gin.Context) {
	// delete auth cookie
	if mw.SendCookie {
		// ？？
		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		// 如果将 Token 作为 Cookie 返回，则删除 Cookie
		c.SetCookie(
			mw.CookieName,
			"",
			-1,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}

	// 执行 退出响应
	mw.LogoutResponse(c, http.StatusOK)
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the GinJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
//
// RefreshHandler 可用于刷新 token。 刷新时 token 仍需有效。
// 应放置在使用 GinJWTMiddleware 的端点下。
// 回复的格式为 {"token": "TOKEN"}。
func (mw *GinJWTMiddleware) RefreshHandler(c *gin.Context) {
	// 刷新 Token，返回新的 token、和有效期
	tokenString, expire, err := mw.RefreshToken(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	mw.RefreshResponse(c, http.StatusOK, tokenString, expire)
}

// RefreshToken refresh token and check if token is expired
// 刷新 token 并且 检查 token 是否过期
func (mw *GinJWTMiddleware) RefreshToken(c *gin.Context) (string, time.Time, error) {
	// 检查 token 是否过期，过期 err 不为 nil
	claims, err := mw.CheckIfTokenExpire(c)
	if err != nil {
		return "", time.Now(), err
	}

	// Create the token
	// 创建新的 token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	// 同步 payload
	for key := range claims {
		newClaims[key] = claims[key]
	}

	// 重新设置 过期时间、生成时间
	expire := mw.TimeFunc().Add(mw.Timeout)
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()

	// 签发 token
	tokenString, err := mw.signedString(newToken)
	if err != nil {
		return "", time.Now(), err
	}

	// set cookie
	if mw.SendCookie {
		// 选择将 token 作为 cookie 返回

		// Cookie 有效期
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - time.Now().Unix())

		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		// 设置 Cookie
		c.SetCookie(
			mw.CookieName,
			tokenString,
			maxage,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}

	return tokenString, expire, nil
}

// CheckIfTokenExpire check if token expire
// 检查 token 是否过期，并返回 Payload
func (mw *GinJWTMiddleware) CheckIfTokenExpire(c *gin.Context) (jwt.MapClaims, error) {
	// 解析 token
	token, err := mw.ParseToken(c)
	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	// 获取 token Payload
	claims := token.Claims.(jwt.MapClaims)

	// 获取 token 生成时间
	origIat := int64(claims["orig_iat"].(float64))

	// 判断 token 是否过期
	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// TokenGenerator method that clients can use to get a jwt token.
// 客户端可以使用 TokenGenerator 方法来获取 jwt token。
func (mw *GinJWTMiddleware) TokenGenerator(data interface{}) (string, time.Time, error) {
	// 创建新的 token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	// 自定义 Payload 处理函数
	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	// token 过期时间、创建时间
	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()

	// 签发 token
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

// ParseTokenString parse jwt token string
// 解析 jwt token 字符串
func (mw *GinJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	// 使用自定义 Key 函数
	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// 校验加密方法
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}

		// 返回公钥进行解密
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// 返回 Key 进行解密
		return mw.Key, nil
	}, mw.ParseOptions...)
}

// 出错或者认证失败时调用
// 向头部写入 WWW-Authenticate: JWT realm=${Realm}
func (mw *GinJWTMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	if !mw.DisabledAbort {
		c.Abort()
	}

	// 回调认证失败函数
	mw.Unauthorized(c, code, message)
}

// ExtractClaims help to extract the JWT claims
// 从 gin 上下文中抽取 Claims
func ExtractClaims(c *gin.Context) MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
// 从 token 中抽取 Claims （Payload）
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
// 从 gin 上下文中查找 "JWT_TOKEN"
func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}
