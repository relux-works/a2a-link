package darwinrelease

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// ArtifactObservation is a read-only, API-authenticated association. Consumers
// still bind its ID/digest/run/source to the expected tag and captured ZIP bytes.
type ArtifactObservation struct {
	ID       int64  `json:"id"`
	RunID    int64  `json:"run_id"`
	JobID    int64  `json:"job_id"`
	Name     string `json:"name"`
	Digest   string `json:"digest"`
	Commit   string `json:"commit"`
	Branch   string `json:"branch"`
	Workflow string `json:"workflow"`
	JobName  string `json:"job_name"`
}

func ObserveArtifact(ctx context.Context, id, runID int64, jobName string) (ArtifactObservation, error) {
	return newGitHub(os.Getenv("GITHUB_TOKEN")).observeArtifact(ctx, id, runID, jobName)
}

func (g *githubAPI) observeArtifact(ctx context.Context, id, runID int64, jobName string) (ArtifactObservation, error) {
	var zero ArtifactObservation
	if id <= 0 || runID <= 0 || jobName == "" {
		return zero, errors.New("artifact-association-input")
	}
	prefix := "/repos/relux-works/a2a-swarm"
	var a struct {
		ID           int64
		Name, Digest string
		Expired      *bool
		Run          struct {
			ID               int64
			RepositoryID     int64  `json:"repository_id"`
			HeadRepositoryID int64  `json:"head_repository_id"`
			HeadSHA          string `json:"head_sha"`
			HeadBranch       string `json:"head_branch"`
		} `json:"workflow_run"`
	}
	if e := g.get(ctx, fmt.Sprintf("%s/actions/artifacts/%d", prefix, id), &a); e != nil {
		return zero, e
	}
	if a.ID != id || a.Run.ID != runID || a.Expired == nil || *a.Expired || a.Name == "" || !objectID.MatchString(a.Run.HeadSHA) || a.Digest == "" {
		return zero, errors.New("artifact-metadata-association")
	}
	var r struct {
		ID                              int64
		HeadSHA                         string `json:"head_sha"`
		HeadBranch                      string `json:"head_branch"`
		Path, Event, Status, Conclusion string
		Repo                            struct {
			ID       int64
			FullName string `json:"full_name"`
		} `json:"repository"`
		HeadRepo struct {
			ID       int64
			FullName string `json:"full_name"`
		} `json:"head_repository"`
	}
	if e := g.get(ctx, fmt.Sprintf("%s/actions/runs/%d", prefix, runID), &r); e != nil {
		return zero, e
	}
	if r.Event != "push" || r.ID != runID || r.HeadSHA != a.Run.HeadSHA || r.HeadBranch != a.Run.HeadBranch || r.Repo.ID <= 0 || r.Repo.ID != a.Run.RepositoryID || r.HeadRepo.ID <= 0 || r.HeadRepo.ID != a.Run.HeadRepositoryID || r.Repo.FullName != "relux-works/a2a-swarm" || r.HeadRepo.FullName != r.Repo.FullName {
		return zero, errors.New("artifact-run-association")
	}
	if !(r.Status == "in_progress" && r.Conclusion == "" || r.Status == "completed" && r.Conclusion == "success") {
		return zero, errors.New("artifact-run-state")
	}
	var jobs struct {
		Count int `json:"total_count"`
		Jobs  []struct {
			ID                       int64
			RunID                    int64  `json:"run_id"`
			HeadSHA                  string `json:"head_sha"`
			Name, Status, Conclusion string
		}
	}
	if e := g.get(ctx, fmt.Sprintf("%s/actions/runs/%d/jobs?filter=latest&per_page=100", prefix, runID), &jobs); e != nil {
		return zero, e
	}
	if jobs.Count != len(jobs.Jobs) || jobs.Count >= 100 {
		return zero, errors.New("artifact-job-list-incomplete")
	}
	n := 0
	jobID := int64(0)
	for _, j := range jobs.Jobs {
		if j.Name != jobName {
			continue
		}
		n++
		if j.ID <= 0 || j.RunID != runID || j.HeadSHA != r.HeadSHA || j.Status != "completed" || j.Conclusion != "success" {
			return zero, errors.New("artifact-producer-job-not-success")
		}
		jobID = j.ID
	}
	if n != 1 {
		return zero, errors.New("artifact-producer-job-ambiguous")
	}
	return ArtifactObservation{id, runID, jobID, a.Name, a.Digest, r.HeadSHA, r.HeadBranch, r.Path, jobName}, nil
}
