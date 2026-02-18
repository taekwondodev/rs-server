#![cfg_attr(not(feature = "strict"), allow(dead_code))]

use crate::app::AppError;

pub struct SelectBuilder {
    columns: Vec<String>,
    from: Option<String>,
    joins: Vec<String>,
    wheres: Vec<String>,
    order_by: Vec<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    param_count: i32,
}

impl SelectBuilder {
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            from: None,
            joins: Vec::new(),
            wheres: Vec::new(),
            order_by: Vec::new(),
            limit: None,
            offset: None,
            param_count: 0,
        }
    }

    pub fn select(mut self, column: &str) -> Self {
        self.columns.push(column.to_string());
        self
    }

    pub fn select_all(mut self) -> Self {
        self.columns.push("*".to_string());
        self
    }

    pub fn from(mut self, table: &str) -> Self {
        self.from = Some(table.to_string());
        self
    }

    pub fn inner_join(mut self, table: &str, on: &str) -> Self {
        self.joins.push(format!("INNER JOIN {} ON {}", table, on));
        self
    }

    pub fn left_join(mut self, table: &str, on: &str) -> Self {
        self.joins.push(format!("LEFT JOIN {} ON {}", table, on));
        self
    }

    pub fn where_clause(mut self, condition: &str) -> Self {
        self.wheres.push(condition.to_string());
        self
    }

    pub fn where_param<T>(mut self, column: &str, _value: &T) -> Self {
        self.param_count += 1;
        self.wheres
            .push(format!("{} = ${}", column, self.param_count));
        self
    }

    pub fn order_by(mut self, column: &str, direction: OrderDirection) -> Self {
        self.order_by
            .push(format!("{} {}", column, direction.as_str()));
        self
    }

    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn build(self) -> Result<String, AppError> {
        if self.from.is_none() {
            return Err(AppError::BadRequest("FROM clause is required".to_string()));
        }

        let columns = if self.columns.is_empty() {
            "*".to_string()
        } else {
            self.columns.join(", ")
        };

        let mut query = format!("SELECT {} FROM {}", columns, self.from.unwrap());

        if !self.joins.is_empty() {
            query.push_str(" ");
            query.push_str(&self.joins.join(" "));
        }

        if !self.wheres.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&self.wheres.join(" AND "));
        }

        if !self.order_by.is_empty() {
            query.push_str(" ORDER BY ");
            query.push_str(&self.order_by.join(", "));
        }

        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = self.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        Ok(query)
    }

    pub fn param_count(&self) -> i32 {
        self.param_count
    }
}

pub struct InsertBuilder {
    table: Option<String>,
    columns: Vec<String>,
    param_count: i32,
    returning: Vec<String>,
}

impl InsertBuilder {
    pub fn new() -> Self {
        Self {
            table: None,
            columns: Vec::new(),
            param_count: 0,
            returning: Vec::new(),
        }
    }

    pub fn into(mut self, table: &str) -> Self {
        self.table = Some(table.to_string());
        self
    }

    pub fn column<T>(mut self, name: &str, _value: &T) -> Self {
        self.columns.push(name.to_string());
        self.param_count += 1;
        self
    }

    pub fn returning(mut self, column: &str) -> Self {
        self.returning.push(column.to_string());
        self
    }

    pub fn returning_all(mut self) -> Self {
        self.returning.push("*".to_string());
        self
    }

    pub fn build(self) -> Result<String, AppError> {
        if self.table.is_none() {
            return Err(AppError::BadRequest("Table name is required".to_string()));
        }
        if self.columns.is_empty() {
            return Err(AppError::BadRequest(
                "At least one column is required".to_string(),
            ));
        }

        let placeholders: Vec<String> = (1..=self.param_count).map(|i| format!("${}", i)).collect();

        let mut query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table.unwrap(),
            self.columns.join(", "),
            placeholders.join(", ")
        );

        if !self.returning.is_empty() {
            query.push_str(" RETURNING ");
            query.push_str(&self.returning.join(", "));
        }

        Ok(query)
    }
}

pub struct UpdateBuilder {
    table: Option<String>,
    sets: Vec<String>,
    wheres: Vec<String>,
    param_count: i32,
    returning: Vec<String>,
}

impl UpdateBuilder {
    pub fn new() -> Self {
        Self {
            table: None,
            sets: Vec::new(),
            wheres: Vec::new(),
            param_count: 0,
            returning: Vec::new(),
        }
    }

    pub fn table(mut self, table: &str) -> Self {
        self.table = Some(table.to_string());
        self
    }

    pub fn set<T>(mut self, column: &str, _value: &Option<T>) -> Self {
        if _value.is_some() {
            self.param_count += 1;
            self.sets
                .push(format!("{} = ${}", column, self.param_count));
        }
        self
    }

    pub fn set_always<T>(mut self, column: &str, _value: &T) -> Self {
        self.param_count += 1;
        self.sets
            .push(format!("{} = ${}", column, self.param_count));
        self
    }

    pub fn where_id(mut self, _id: i32) -> Self {
        self.param_count += 1;
        self.wheres.push(format!("id = ${}", self.param_count));
        self
    }

    pub fn where_clause(mut self, condition: &str) -> Self {
        self.wheres.push(condition.to_string());
        self
    }

    pub fn where_param<T>(mut self, column: &str, _value: &T) -> Self {
        self.param_count += 1;
        self.wheres
            .push(format!("{} = ${}", column, self.param_count));
        self
    }

    pub fn returning(mut self, column: &str) -> Self {
        self.returning.push(column.to_string());
        self
    }

    pub fn returning_all(mut self) -> Self {
        self.returning.push("*".to_string());
        self
    }

    pub fn build(self) -> Result<String, AppError> {
        if self.table.is_none() {
            return Err(AppError::BadRequest("Table name is required".to_string()));
        }
        if self.sets.is_empty() {
            return Err(AppError::BadRequest(
                "At least one SET clause is required".to_string(),
            ));
        }
        if self.wheres.is_empty() {
            return Err(AppError::BadRequest(
                "WHERE clause is required for UPDATE".to_string(),
            ));
        }

        let mut query = format!(
            "UPDATE {} SET {}",
            self.table.unwrap(),
            self.sets.join(", ")
        );

        query.push_str(" WHERE ");
        query.push_str(&self.wheres.join(" AND "));

        if !self.returning.is_empty() {
            query.push_str(" RETURNING ");
            query.push_str(&self.returning.join(", "));
        }

        Ok(query)
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

pub struct DeleteBuilder {
    table: Option<String>,
    wheres: Vec<String>,
    param_count: i32,
}

impl DeleteBuilder {
    pub fn new() -> Self {
        Self {
            table: None,
            wheres: Vec::new(),
            param_count: 0,
        }
    }

    pub fn from(mut self, table: &str) -> Self {
        self.table = Some(table.to_string());
        self
    }

    pub fn where_clause(mut self, condition: &str) -> Self {
        self.wheres.push(condition.to_string());
        self
    }

    pub fn where_param<T>(mut self, column: &str, _value: &T) -> Self {
        self.param_count += 1;
        self.wheres
            .push(format!("{} = ${}", column, self.param_count));
        self
    }

    pub fn build(self) -> Result<String, AppError> {
        if self.table.is_none() {
            return Err(AppError::BadRequest("Table name is required".to_string()));
        }
        if self.wheres.is_empty() {
            return Err(AppError::BadRequest(
                "WHERE clause is required for DELETE".to_string(),
            ));
        }

        let mut query = format!("DELETE FROM {}", self.table.unwrap());

        query.push_str(" WHERE ");
        query.push_str(&self.wheres.join(" AND "));

        Ok(query)
    }
}

pub enum OrderDirection {
    Asc,
    Desc,
}

impl OrderDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderDirection::Asc => "ASC",
            OrderDirection::Desc => "DESC",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_builder_basic() {
        let query = SelectBuilder::new()
            .select("id")
            .select("name")
            .from("users")
            .build()
            .unwrap();

        assert_eq!(query, "SELECT id, name FROM users");
    }

    #[test]
    fn test_select_builder_with_where() {
        let username = "test";
        let query = SelectBuilder::new()
            .select_all()
            .from("users")
            .where_param("username", &username)
            .build()
            .unwrap();

        assert_eq!(query, "SELECT * FROM users WHERE username = $1");
    }

    #[test]
    fn test_select_builder_with_join() {
        let query = SelectBuilder::new()
            .select("u.id")
            .select("c.passkey")
            .from("users u")
            .inner_join("credentials c", "u.id = c.user_id")
            .where_clause("u.status = 'active'")
            .build()
            .unwrap();

        assert_eq!(
            query,
            "SELECT u.id, c.passkey FROM users u INNER JOIN credentials c ON u.id = c.user_id WHERE u.status = 'active'"
        );
    }

    #[test]
    fn test_insert_builder() {
        let name = "product";
        let price = 100;
        let query = InsertBuilder::new()
            .into("products")
            .column("name", &name)
            .column("price", &price)
            .returning_all()
            .build()
            .unwrap();

        assert_eq!(
            query,
            "INSERT INTO products (name, price) VALUES ($1, $2) RETURNING *"
        );
    }

    #[test]
    fn test_update_builder() {
        let name = Some("new_name");
        let price = Some(200);
        let query = UpdateBuilder::new()
            .table("products")
            .set("name", &name)
            .set("price", &price)
            .where_id(1)
            .returning_all()
            .build()
            .unwrap();

        assert_eq!(
            query,
            "UPDATE products SET name = $1, price = $2 WHERE id = $3 RETURNING *"
        );
    }

    #[test]
    fn test_update_builder_skip_none() {
        let name: Option<String> = None;
        let price = Some(200);
        let query = UpdateBuilder::new()
            .table("products")
            .set("name", &name)
            .set("price", &price)
            .where_id(1)
            .build()
            .unwrap();

        assert_eq!(query, "UPDATE products SET price = $1 WHERE id = $2");
    }

    #[test]
    fn test_delete_builder() {
        let id = 1;
        let query = DeleteBuilder::new()
            .from("products")
            .where_param("id", &id)
            .build()
            .unwrap();

        assert_eq!(query, "DELETE FROM products WHERE id = $1");
    }
}
