# API bootstrap

Install with Python 3.11+:

    pip install -r requirements.txt
    uvicorn main:app --reload

Health: GET /health
Catalog: GET /v1/tools
Plan only: POST /v1/jobs/plan

This scaffold intentionally does not execute scanners and is not production-safe yet. Authentication, Supabase JWT verification, workspace membership checks, asset scope resolution, audit writes, queue integration, and worker isolation must be completed before public deployment. Render auto-deploy is disabled in render.yaml for this reason.
