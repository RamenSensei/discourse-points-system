package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"github.com/forum-points/ledger/internal/merkle"
	"github.com/forum-points/ledger/internal/txlog"
)

// installTxLogRoutes registers the /log/* endpoints if a txlog service is configured.
func (s *Server) installTxLogRoutes() {
	if s.TxLog == nil {
		return
	}
	s.r.Get("/api/v1/log/sth", s.logSTH)
	s.r.Get("/api/v1/log/leaves", s.logLeaves)
	s.r.Get("/api/v1/log/inclusion", s.logInclusion)
	s.r.Get("/api/v1/log/consistency", s.logConsistency)
	s.r.Get("/api/v1/log/checkpoints", s.logCheckpoints)
}

func (s *Server) logSTH(w http.ResponseWriter, r *http.Request) {
	sth, err := s.TxLog.CurrentSTH(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sth)
}

func (s *Server) logLeaves(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	from, _ := strconv.ParseInt(fromStr, 10, 64)
	to := int64(-1)
	if toStr != "" {
		var err error
		to, err = strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("bad to"))
			return
		}
	}
	leaves, err := s.TxLog.RangeLeaves(r.Context(), from, to)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from":   from,
		"to":     to,
		"count":  len(leaves),
		"leaves": leaves,
	})
}

func (s *Server) logInclusion(w http.ResponseWriter, r *http.Request) {
	idxStr := r.URL.Query().Get("leaf_index")
	sizeStr := r.URL.Query().Get("tree_size")
	idx, err := strconv.ParseInt(idxStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("bad leaf_index"))
		return
	}
	totalSize, err := s.TxLog.CurrentTreeSize(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	sz := totalSize
	if sizeStr != "" {
		sz, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || sz <= 0 || sz > totalSize {
			writeErr(w, http.StatusBadRequest, errors.New("bad tree_size"))
			return
		}
	}
	if idx < 0 || idx >= sz {
		writeErr(w, http.StatusBadRequest, errors.New("leaf_index out of range"))
		return
	}
	leafHashes, err := s.TxLog.LeafHashes(r.Context(), sz)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	proof, err := merkle.InclusionProofFromHashes(leafHashes, int(idx))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	proofHex := make([]string, len(proof))
	for i, p := range proof {
		proofHex[i] = hex.EncodeToString(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"leaf_index":    idx,
		"tree_size":     sz,
		"leaf_hash_hex": hex.EncodeToString(leafHashes[idx]),
		"audit_path":    proofHex,
	})
}

func (s *Server) logConsistency(w http.ResponseWriter, r *http.Request) {
	firstStr := r.URL.Query().Get("first")
	secondStr := r.URL.Query().Get("second")
	first, err1 := strconv.ParseInt(firstStr, 10, 64)
	second, err2 := strconv.ParseInt(secondStr, 10, 64)
	if err1 != nil || err2 != nil || first <= 0 || second < first {
		writeErr(w, http.StatusBadRequest, errors.New("require 0 < first <= second"))
		return
	}
	totalSize, err := s.TxLog.CurrentTreeSize(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if second > totalSize {
		writeErr(w, http.StatusBadRequest, errors.New("second exceeds current tree size"))
		return
	}
	leafHashes, err := s.TxLog.LeafHashes(r.Context(), second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	proof, err := merkle.ConsistencyProofFromHashes(leafHashes, int(first), int(second))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	proofHex := make([]string, len(proof))
	for i, p := range proof {
		proofHex[i] = hex.EncodeToString(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"first":  first,
		"second": second,
		"proof":  proofHex,
	})
}

// TxLog service plumbing — used by main.go to wire the optional service.
type TxLogService = txlog.Service

func (s *Server) logCheckpoints(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, e := strconv.Atoi(l); e == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	cps, err := s.TxLog.Checkpoints(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":       len(cps),
		"checkpoints": cps,
	})
}
