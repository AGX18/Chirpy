package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"os"

	"github.com/AGX18/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
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

		userUUID, err := uuid.Parse(params.UserID)
		if err != nil {
			fmt.Printf("Invalid UUID received: '%s', length: %d, error: %v\n", params.UserID, len(params.UserID), err)
			respondWithError(w, 400, fmt.Sprintf("Invalid user ID format: %s", params.UserID))
			return
		}

		createdChirp, err := apiCfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{Body: returnedBody, UserID: userUUID})
		if err != nil {
			fmt.Printf("Failed to create chirp: %v\n", err)
			respondWithError(w, 500, "Failed to create chirp")
			return
		}

		respondWithJSON(w, http.StatusCreated, createdChirp)

	})

	serverMux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		allChirps, err := apiCfg.DB.GetAllChirps(r.Context())
		if err != nil {
			fmt.Printf("Failed to get chirps: %v\n", err)
			respondWithError(w, 500, "Failed to get chirps")
			return
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

		respondWithJSON(w, http.StatusOK, chirp)

	})

	serverMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		email := json.NewDecoder(r.Body)
		params := UserParams{}
		if err := email.Decode(&params); err != nil {
			respondWithError(w, 400, "Invalid request body")
			return
		}

		createdUser, err := apiCfg.DB.CreateUser(r.Context(), params.Email)
		if err != nil {
			respondWithError(w, 500, "Failed to create user")
			return
		}

		respondWithJSON(w, http.StatusCreated, createdUser)
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

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
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
	Email string `json:"email"`
}

type ChirpParams struct {
	Body   string `json:"body"`
	UserID string `json:"user_id"`
}
