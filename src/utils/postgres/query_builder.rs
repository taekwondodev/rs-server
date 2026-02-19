#![cfg_attr(not(feature = "strict"), allow(dead_code))]

use crate::app::AppError;

trait WhereClause {
    fn wheres_mut(&mut self) -> &mut Vec<String>;
    fn param_count_mut(&mut self) -> &mut i32;

    fn where_clause(mut self, condition: &str) -> Self
    where
        Self: Sized,
    {
        self.wheres_mut().push(condition.to_string());
        self
    }

    fn where_param<T>(mut self, column: &str, _value: &T) -> Self
    where
        Self: Sized,
    {
        *self.param_count_mut() += 1;
        let count = *self.param_count_mut();
        self.wheres_mut().push(format!("{} = ${}", column, count));
        self
    }
}

trait ReturningClause {
    fn returning_mut(&mut self) -> &mut Vec<String>;

    fn returning(mut self, column: &str) -> Self
    where
        Self: Sized,
    {
        self.returning_mut().push(column.to_string());
        self
    }

    fn returning_all(mut self) -> Self
    where
        Self: Sized,
    {
        self.returning_mut().push("*".to_string());
        self
    }
}

struct QueryFragment {
    base: String,
}

impl QueryFragment {
    fn new(base: String) -> Self {
        Self { base }
    }

    fn append_if(mut self, prefix: &str, items: &[String], separator: &str) -> Self {
        if !items.is_empty() {
            if !prefix.is_empty() {
                self.base.push(' ');
                self.base.push_str(prefix);
                self.base.push(' ');
                self.base.push_str(&items.join(separator));
            } else {
                self.base.push(' ');
                self.base.push_str(&items.join(separator));
            }
        }
        self
    }

    fn append_option(mut self, prefix: &str, value: Option<i64>) -> Self {
        if let Some(v) = value {
            self.base.push_str(&format!(" {} {}", prefix, v));
        }
        self
    }

    fn build(self) -> String {
        self.base
    }
}

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
            "*"
        } else {
            &self.columns.join(", ")
        };

        let base = format!("SELECT {} FROM {}", columns, self.from.unwrap());

        let query = QueryFragment::new(base)
            .append_if("", &self.joins, " ")
            .append_if("WHERE", &self.wheres, " AND ")
            .append_if("ORDER BY", &self.order_by, ", ")
            .append_option("LIMIT", self.limit)
            .append_option("OFFSET", self.offset)
            .build();

        Ok(query)
    }

    pub fn param_count(&self) -> i32 {
        self.param_count
    }
}

impl WhereClause for SelectBuilder {
    fn wheres_mut(&mut self) -> &mut Vec<String> {
        &mut self.wheres
    }

    fn param_count_mut(&mut self) -> &mut i32 {
        &mut self.param_count
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

        let base = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table.unwrap(),
            self.columns.join(", "),
            placeholders.join(", ")
        );

        let query = QueryFragment::new(base)
            .append_if("RETURNING", &self.returning, ", ")
            .build();

        Ok(query)
    }
}

impl ReturningClause for InsertBuilder {
    fn returning_mut(&mut self) -> &mut Vec<String> {
        &mut self.returning
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

        let base = format!(
            "UPDATE {} SET {}",
            self.table.unwrap(),
            self.sets.join(", ")
        );

        let query = QueryFragment::new(base)
            .append_if("WHERE", &self.wheres, " AND ")
            .append_if("RETURNING", &self.returning, ", ")
            .build();

        Ok(query)
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

impl WhereClause for UpdateBuilder {
    fn wheres_mut(&mut self) -> &mut Vec<String> {
        &mut self.wheres
    }

    fn param_count_mut(&mut self) -> &mut i32 {
        &mut self.param_count
    }
}

impl ReturningClause for UpdateBuilder {
    fn returning_mut(&mut self) -> &mut Vec<String> {
        &mut self.returning
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

    pub fn build(self) -> Result<String, AppError> {
        if self.table.is_none() {
            return Err(AppError::BadRequest("Table name is required".to_string()));
        }
        if self.wheres.is_empty() {
            return Err(AppError::BadRequest(
                "WHERE clause is required for DELETE".to_string(),
            ));
        }

        let base = format!("DELETE FROM {}", self.table.unwrap());

        let query = QueryFragment::new(base)
            .append_if("WHERE", &self.wheres, " AND ")
            .build();

        Ok(query)
    }
}

impl WhereClause for DeleteBuilder {
    fn wheres_mut(&mut self) -> &mut Vec<String> {
        &mut self.wheres
    }

    fn param_count_mut(&mut self) -> &mut i32 {
        &mut self.param_count
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
