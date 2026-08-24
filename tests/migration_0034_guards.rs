use asf::ledger::PgLedger;
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

struct ScopedDatabase {
    ledger: PgLedger,
    admin: PgPool,
    schema: String,
}

impl ScopedDatabase {
    async fn create(database_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let admin = PgPool::connect(database_url).await?;
        let schema = format!("asf_migration_test_{}", Uuid::now_v7().simple());

        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await?;

        let mut scoped_url = Url::parse(database_url)?;
        scoped_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let ledger = PgLedger::connect(scoped_url.as_str()).await?;
        ledger.migrate().await?;

        Ok(Self {
            ledger,
            admin,
            schema,
        })
    }

    async fn cleanup(self) -> Result<(), Box<dyn std::error::Error>> {
        self.ledger.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn migration_0034_stream_guards_applies_successfully() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        println!("Skipping test: DATABASE_URL not set");
        return;
    };

    let db = ScopedDatabase::create(&database_url)
        .await
        .expect("create scoped database with migrations");

    // If we get here, all migrations including 0034 have applied successfully
    println!("✓ Migration 0034 applied successfully");

    db.cleanup().await.expect("cleanup scoped database");
}
