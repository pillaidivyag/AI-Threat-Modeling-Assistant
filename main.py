from pipeline import run_threat_modelling_pipeline

if __name__ == "__main__":
    sample_app_desc = (
        "A customer web portal connected via REST API to a PostgreSQL database. "
        "Support staff use an administrator portal that communicates with the backend."
    )
    run_threat_modelling_pipeline(sample_app_desc)