# Deployment Architecture

**Source:** [API_First.md](API_First.md) - Section 11

---

## 11.1 Local Development (Docker Compose)

```
docker-compose.yml
├── api          FastAPI           :8000   (Dockerfile.api)
├── web-ui       Next.js           :3000   (Dockerfile.ui)
├── scanner      Security tools    on-demand (Dockerfile.scanner)
├── db           PostgreSQL 15     :5432
├── redis        Redis 7           :6379
├── minio        MinIO (S3)        :9009 / :9001 (console)
├── mailhog      SMTP testing      :1025 / :8025 (web)
└── session-cleanup  Redis cleanup  periodic
```

## 11.2 Production (AWS ECS Fargate)

```
                    ┌───────────────────────────────────────────┐
                    │              AWS Cloud                     │
                    │                                           │
                    │  ┌─────────────────────────────────────┐  │
                    │  │       Application Load Balancer     │  │
                    │  │   ┌──────────┐  ┌──────────────┐   │  │
                    │  │   │ :443/api │  │ :443 (root)  │   │  │
                    │  │   └────┬─────┘  └──────┬───────┘   │  │
                    │  └────────┼────────────────┼───────────┘  │
                    │           │                │              │
                    │  ┌────────▼────────┐ ┌────▼──────────┐   │
                    │  │  ECS Service    │ │ ECS Service   │   │
                    │  │  API (Fargate)  │ │ WebUI(Fargate)│   │
                    │  │  2 tasks        │ │ 2 tasks       │   │
                    │  │  Auto-scaling   │ │ Auto-scaling  │   │
                    │  └────────┬────────┘ └───────────────┘   │
                    │           │                               │
                    │  ┌────────▼──────────────────────────┐   │
                    │  │         Private Subnets            │   │
                    │  │  ┌──────────┐  ┌──────────────┐   │   │
                    │  │  │  RDS     │  │ ElastiCache  │   │   │
                    │  │  │ Postgres │  │ Redis        │   │   │
                    │  │  │ Multi-AZ │  │ Failover     │   │   │
                    │  │  └──────────┘  └──────────────┘   │   │
                    │  │  ┌──────────┐                     │   │
                    │  │  │  S3      │                     │   │
                    │  │  │ Reports  │                     │   │
                    │  │  │ & Logs   │                     │   │
                    │  │  └──────────┘                     │   │
                    │  └───────────────────────────────────┘   │
                    │                                           │
                    │  ┌───────────────────────────────────┐   │
                    │  │  ECR Repositories                 │   │
                    │  │  ├── auditgh-api                  │   │
                    │  │  ├── auditgh-webui                │   │
                    │  │  └── auditgh-scanner              │   │
                    │  └───────────────────────────────────┘   │
                    └───────────────────────────────────────────┘
```

**Infrastructure as Code:** Terraform modules in `infrastructure/terraform/modules/` cover VPC, security groups, IAM, ECR, RDS, ElastiCache, S3, ALB, ECS cluster, and ECS services.

**CI/CD:** GitHub Actions workflow (`.github/workflows/deploy-ecs.yml`) builds all three container images, pushes to ECR, and deploys to ECS with health verification.
