package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"os"

	"github.com/AGX18/Chirpy/internal/auth"
	"github.com/AGX18/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	POLKA_KEY := os.Getenv("POLKA_KEY")
	if jwtSecret == "" {
		panic("JWT_SECRET environment variable is not set")
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}
	dbQueries := database.New(db)
	serverMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		DB:             dbQueries,
		Platform:       os.Getenv("PLATFORM"),
		JwtSecret:      jwtSecret,
		POLKA_KEY:      POLKA_KEY,
	}

	serverMux.Handle("GET /admin/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w,
			`<html>
			<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
			</body>
			</html>`,
			apiCfg.fileserverHits.Load())
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
	}))

	serverMux.Handle("POST /admin/reset", apiCfg.middlewareResetServerHits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiCfg.Platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := apiCfg.DB.Reset(r.Context()); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to reset database")
			return
		}
		w.WriteHeader(http.StatusOK)
	})))

	serverMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	serverMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	serverMux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := ChirpParams{}
		if err := decoder.Decode(&params); err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}

		if len(params.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}
		returnedBody := replaceProfaneWords(params.Body)

		// userUUID, err := uuid.Parse(params.UserID)
		// if err != nil {
		// 	fmt.Printf("Invalid UUID received: '%s', length: %d, error: %v\n", params.UserID, len(params.UserID), err)
		// 	respondWithError(w, 400, fmt.Sprintf("Invalid user ID format: %s", params.UserID))
		// 	return
		// }

		GetBearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "Wrong or missing authorization token")
			return
		}
		userUUID, err := auth.ValidateJWT(GetBearerToken, apiCfg.JwtSecret)
		if err != nil {
			respondWithError(w, 401, "Invalid or expired token")
			return
		}

		createdChirp, err := apiCfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{Body: returnedBody, UserID: userUUID})
		if err != nil {
			fmt.Printf("Failed to create chirp: %v\n", err)
			respondWithError(w, 500, "Failed to create chirp")
			return
		}

		respondWithJSON(w, http.StatusCreated, Chirp{
			ID:        createdChirp.ID,
			CreatedAt: createdChirp.CreatedAt,
			UpdatedAt: createdChirp.UpdatedAt,
			Body:      createdChirp.Body,
			UserID:    createdChirp.UserID,
		})

	})

	serverMux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		authorID := r.URL.Query().Get("author_id")

		var allChirps []database.Chirp
		var err error
		if authorID != "" {
			authorUUID, err := uuid.Parse(authorID)
			if err != nil {
				respondWithError(w, 400, "Invalid author ID format")
				return
			}
			allChirps, err = apiCfg.DB.GetAllChirpsByAuthor(r.Context(), authorUUID)
			if err == sql.ErrNoRows {
				respondWithError(w, 404, "No chirps found for this author")
				return
			}
		} else {
			allChirps, err = apiCfg.DB.GetAllChirps(r.Context())
		}

		if err != nil {
			fmt.Printf("Failed to get chirps: %v\n", err)
			respondWithError(w, 500, "Failed to get chirps")
			return
		}

		// optional sorting by created_at asc or desc
		// this is not implemented in the database, so we will sort it in memory
		// asc is the default sorting and it's done by the database
		sorting := r.URL.Query().Get("sort")

		if sorting == "desc" {
			sort.Slice(allChirps, func(i, j int) bool {
				return allChirps[i].CreatedAt.After(allChirps[j].CreatedAt)
			})
		}
		respondWithJSON(w, http.StatusOK, allChirps)

	})

	serverMux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("chirpID")
		chirpID, err := uuid.Parse(id)
		if err != nil {
			respondWithError(w, 400, "wrong chirp ID format")
			return
		}

		chirp, err := apiCfg.DB.GetChirpByID(r.Context(), chirpID)
		if err == sql.ErrNoRows {
			respondWithError(w, 404, "Chirp not found")
			return
		}

		if err != nil {
			respondWithError(w, 500, "Failed to get chirp")
			return
		}

		respondWithJSON(w, http.StatusOK, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})

	})

	serverMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		email := json.NewDecoder(r.Body)
		params := UserParams{}
		if err := email.Decode(&params); err != nil {
			respondWithError(w, 400, "Invalid request body")
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			respondWithError(w, 500, "Failed to hash password")
			return
		}

		createdUser, err := apiCfg.DB.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword})
		if err != nil {
			respondWithError(w, 500, "Failed to create user")
			return
		}

		respondWithJSON(w, http.StatusCreated, User{
			ID:          createdUser.ID,
			CreatedAt:   createdUser.CreatedAt,
			UpdatedAt:   createdUser.UpdatedAt,
			Email:       createdUser.Email,
			IsChirpyRed: createdUser.IsChirpyRed,
		})
	})

	// This endpoint should allow a user to login.
	// TODO: give the user a token that they can use to make authenticated requests.
	serverMux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := UserParams{}
		if err := decoder.Decode(&params); err != nil {
			respondWithError(w, 400, "Invalid request body")
			return
		}

		user, err := apiCfg.DB.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, 404, "User not found")
				return
			}
			respondWithError(w, 500, "Failed to get user")
			return
		}

		if err := auth.CheckPasswordHash(params.Password, user.HashedPassword); err != nil {
			respondWithError(w, 401, "Incorrect email or password")
			return
		}

		token, err := auth.MakeJWT(user.ID, apiCfg.JwtSecret, time.Hour)
		if err != nil {
			respondWithError(w, 500, "Failed to create JWT token")
			return
		}

		// make a refresh token
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, 500, "Failed to create refresh token")
			return
		}

		// store the refresh token in the database
		_, err = apiCfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:  refreshToken,
			UserID: user.ID,
		})
		if err != nil {
			respondWithError(w, 500, "Failed to store refresh token")
			return
		}

		respondWithJSON(w, http.StatusOK, User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
		})
	})

	serverMux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "Missing or invalid authorization token")
			return
		}
		refreshToken, err := apiCfg.DB.GetUserFromRefreshToken(r.Context(), token)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, 401, "Refresh token not found or expired")
				return
			}
			respondWithError(w, 500, "Failed to validate refresh token")
			return
		}

		if refreshToken.RevokedAt.Valid {
			respondWithError(w, 401, "Refresh token has been revoked")
			return
		}

		accessToken, err := auth.MakeJWT(refreshToken.UserID, apiCfg.JwtSecret, time.Hour)
		if err != nil {
			respondWithError(w, 500, "Failed to create access token")
			return
		}

		respondWithJSON(w, http.StatusOK, AccessTokenResponse{
			Token: accessToken,
		})

	})

	serverMux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "Missing or invalid authorization token")
			return
		}

		// revoke the refresh token by setting the revoked_at field to the current time
		result, err := apiCfg.DB.RevokeRefreshToken(r.Context(), token)

		if err != nil {
			respondWithError(w, 500, "Failed to revoke refresh token")
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			respondWithError(w, 500, "Internal server error")
			return
		}

		if rowsAffected == 0 {
			respondWithError(w, 404, "Refresh token not found")
			return
		}

		respondWithJSON(w, 204, nil)

	})

	serverMux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "Missing or invalid authorization token")
			return
		}

		id, err := auth.ValidateJWT(token, apiCfg.JwtSecret)
		if err != nil {
			respondWithError(w, 401, "invalid or revoked Token")
			return
		}

		// contains new password and email
		userParams := UserParams{}
		err = json.NewDecoder(r.Body).Decode(&userParams)
		if err != nil {
			respondWithError(w, 500, "internal server error")
		}

		hashedPassword, err := auth.HashPassword(userParams.Password)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "internal server error")
		}

		updatedUser, err := apiCfg.DB.UpdateEmailAndPassword(r.Context(), database.UpdateEmailAndPasswordParams{
			Email:          userParams.Email,
			HashedPassword: hashedPassword,
			ID:             id,
		})

		if err != nil {
			respondWithError(w, 500, "internal server error")
		}

		respondWithJSON(w, http.StatusOK, User{
			ID:          updatedUser.ID,
			CreatedAt:   updatedUser.CreatedAt,
			UpdatedAt:   updatedUser.UpdatedAt,
			Email:       updatedUser.Email,
			IsChirpyRed: updatedUser.IsChirpyRed,
		})

	})

	// deletes a chirp from the database by its id.
	serverMux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "Missing or invalid authorization token")
			return
		}

		chirpIDString := r.PathValue("chirpID")

		if chirpIDString == "" {
			respondWithError(w, http.StatusBadRequest, "Invalid Request")
			return
		}

		chirpID, err := uuid.Parse(chirpIDString)
		if err != nil {
			respondWithError(w, 400, "wrong chirp ID format")
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.JwtSecret)
		if err != nil {
			respondWithError(w, 401, "invalid or revoked Token")
			return
		}

		// get the chirp and check if the ids match

		chirp, err := apiCfg.DB.GetChirpByID(r.Context(), chirpID)

		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "Chirp not found")
				return
			}
			respondWithError(w, 500, "internal server error")
			return
		}

		if chirp.UserID != userID {
			respondWithError(w, 403, "Unauthorized")
			return
		}

		err = apiCfg.DB.DeleteChirpByID(r.Context(), chirpID)

		if err != nil {
			respondWithError(w, 500, "internal server error: could not delete chirp")
			return
		}
		respondWithJSON(w, 204, nil)

	})

	serverMux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		PolkaKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			respondWithError(w, 401, "Missing or invalid API key")
			return
		}

		if PolkaKey != apiCfg.POLKA_KEY {
			respondWithError(w, 401, "Forbidden: Invalid API key")
			return
		}
		var chirpRequest ChirpRequest
		if err := json.NewDecoder(r.Body).Decode(&chirpRequest); err != nil {
			respondWithError(w, 400, "Invalid request body")
			return
		}

		if chirpRequest.Event != "user.upgraded" {
			respondWithJSON(w, 204, nil)
			return
		}

		_, err = apiCfg.DB.MakeUserChirpyRed(r.Context(), chirpRequest.Data.UserID)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, 404, "User not found")
				return
			}
			// Log the error for debugging purposes
			fmt.Printf("Failed to make user chirpy red: %v\n", err)
			respondWithError(w, 500, "Failed to make user chirpy red")
			return
		}

		respondWithJSON(w, 204, nil)
	})

	server.ListenAndServe()

}

func replaceProfaneWords(text string) string {
	// strings.ToLower
	// strings.Split
	// strings.Join
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(text, " ")
	for _, word := range profaneWords {
		for i, w := range words {
			if strings.ToLower(w) == word {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if payload == nil {
		w.WriteHeader(code)
		return
	}
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Error{Error: msg})
}

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
	JwtSecret      string
	POLKA_KEY      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
func (cfg *apiConfig) middlewareResetServerHits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Store(0)
		next.ServeHTTP(w, r)
	})
}

type ReturnedBody struct {
	CleanedBody string `json:"cleaned_body"`
}

type Error struct {
	Error string `json:"error"`
}

type UserParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ChirpParams struct {
	Body   string `json:"body"`
	UserID string `json:"user_id"`
}

type User struct {
	ID           uuid.UUID    `json:"id"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    sql.NullTime `json:"updated_at"`
	Email        string       `json:"email"`
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	IsChirpyRed  bool         `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID    `json:"id"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt sql.NullTime `json:"updated_at"`
	Body      string       `json:"body"`
	UserID    uuid.UUID    `json:"user_id"`
}

type RefreshTokenResponse struct {
	Token     string
	CreatedAt time.Time
	UpdatedAt time.Time
	UserID    uuid.UUID
	ExpiresAt time.Time
	RevokedAt sql.NullTime
}

type AccessTokenResponse struct {
	Token string `json:"token"`
}

type ChirpRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
}
