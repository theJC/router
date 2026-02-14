//! Fragment Validation Performance Benchmark
//!
//! Tests validation performance with various fragment patterns to ensure
//! linear complexity and detect any exponential scaling issues.
//!
//! Related: GHSA-3j43-9v8v-cp3f (Router Fragment Validation Vulnerability)
//!
//! Run with: `cargo build --release --bench fragment_validation && ./target/release/fragment_validation`

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::time::Duration;
use std::time::Instant;

/// Test schema with sufficient variety for fragment testing
const TEST_SCHEMA: &str = r#"
type Query {
  field1: ObjectType
  field2: ObjectType
  field3: ObjectType
  field4: ObjectType
  field5: ObjectType
  field6: ObjectType
  field7: ObjectType
  field8: ObjectType
  field9: ObjectType
  field10: ObjectType
  field11: ObjectType
  field12: ObjectType
  field13: ObjectType
  field14: ObjectType
  field15: ObjectType
  field16: ObjectType
  field17: ObjectType
  field18: ObjectType
  field19: ObjectType
  field20: ObjectType
  field21: ObjectType
  field22: ObjectType
  field23: ObjectType
  field24: ObjectType
  field25: ObjectType
  field26: ObjectType
  field27: ObjectType
  field28: ObjectType
  field29: ObjectType
  field30: ObjectType
  field31: ObjectType
  field32: ObjectType
  field33: ObjectType
  field34: ObjectType
  field35: ObjectType
  field36: ObjectType
  field37: ObjectType
  field38: ObjectType
  field39: ObjectType
  field40: ObjectType
  field41: ObjectType
  field42: ObjectType
  field43: ObjectType
  field44: ObjectType
  field45: ObjectType
  field46: ObjectType
  field47: ObjectType
  field48: ObjectType
  field49: ObjectType
  field50: ObjectType
}

type ObjectType {
  subField1: String
  subField2: Int
  subField3: Boolean
  subField4: Float
  subField5: ID
  nested: NestedType
}

type NestedType {
  nestedField1: String
  nestedField2: Int
  deep: DeepType
}

type DeepType {
  deepField1: String
  deepField2: Int
}
"#;

struct BenchmarkResult {
    test_name: String,
    fragment_count: usize,
    nesting_depth: usize,
    reuse_factor: usize,
    validation_time_us: u64,
    parse_time_us: u64,
}

impl BenchmarkResult {
    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.test_name,
            self.fragment_count,
            self.nesting_depth,
            self.reuse_factor,
            self.validation_time_us,
            self.parse_time_us
        )
    }
}

#[tokio::main]
async fn main() {
    println!("Fragment Validation Performance Benchmark");
    println!("==========================================\n");

    let mut results = Vec::new();

    // Test Category 1: Progressive Fragment Count
    println!("=== Test 1: Progressive Fragment Count ===");
    println!("Testing linear scaling with increasing fragment count...\n");
    println!(
        "{:>4} | {:>12} | {:>12} | {:>8}",
        "Frags", "Validation", "Parse", "Ratio"
    );
    println!("{:-<4}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");

    let mut prev_validation_time = None;
    for count in [10, 20, 30, 40, 50, 75, 100, 150, 200, 300, 500, 750, 1000] {
        let result = test_simple_fragments(count);
        let ratio = if let Some(prev) = prev_validation_time {
            result.validation_time_us as f64 / prev as f64
        } else {
            1.0
        };

        println!(
            "{:>4} | {:>10.3} ms | {:>10.3} ms | {:>7.2}x",
            count,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0,
            ratio
        );

        prev_validation_time = Some(result.validation_time_us);
        results.push(result);
    }

    // Test Category 2: Nested Fragment Depth
    println!("\n=== Test 2: Nested Fragment Depth ===");
    println!("Testing scaling with fragment nesting depth...\n");
    println!(
        "{:>6} | {:>12} | {:>12} | {:>8}",
        "Depth", "Validation", "Parse", "Ratio"
    );
    println!("{:-<6}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");

    let mut prev_validation_time = None;
    for depth in [5, 10, 15, 20, 25, 30, 40, 50, 75, 100] {
        let result = test_nested_fragments(depth);
        let ratio = if let Some(prev) = prev_validation_time {
            result.validation_time_us as f64 / prev as f64
        } else {
            1.0
        };

        println!(
            "{:>6} | {:>10.3} ms | {:>10.3} ms | {:>7.2}x",
            depth,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0,
            ratio
        );

        prev_validation_time = Some(result.validation_time_us);
        results.push(result);
    }

    // Test Category 3: Fragment Reuse
    println!("\n=== Test 3: Fragment Reuse ===");
    println!("Testing validation with repeated fragment spreads...\n");
    println!(
        "{:>6} | {:>12} | {:>12} | {:>8}",
        "Reuse", "Validation", "Parse", "Ratio"
    );
    println!("{:-<6}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");

    let mut prev_validation_time = None;
    for reuse in [10, 25, 50, 100, 200, 500, 1000] {
        let result = test_fragment_reuse(reuse);
        let ratio = if let Some(prev) = prev_validation_time {
            result.validation_time_us as f64 / prev as f64
        } else {
            1.0
        };

        println!(
            "{:>6} | {:>10.3} ms | {:>10.3} ms | {:>7.2}x",
            reuse,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0,
            ratio
        );

        prev_validation_time = Some(result.validation_time_us);
        results.push(result);
    }

    // Test Category 4: Pathological Case (Nested + Reused)
    println!("\n=== Test 4: Pathological Case (Nested + Reused) ===");
    println!("Testing worst-case scenario from CVE...\n");
    println!(
        "{:>6} | {:>6} | {:>12} | {:>12}",
        "Depth", "Reuse", "Validation", "Parse"
    );
    println!("{:-<6}-+-{:-<6}-+-{:-<12}-+-{:-<12}", "", "", "", "");

    for (depth, reuse) in [
        (5, 2),
        (5, 5),
        (10, 2),
        (10, 5),
        (15, 3),
        (20, 5),
        (25, 5),
        (30, 10),
    ] {
        let result = test_pathological_case(depth, reuse);

        println!(
            "{:>6} | {:>6} | {:>10.3} ms | {:>10.3} ms",
            depth,
            reuse,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0
        );

        results.push(result);
    }

    // Test Category 5: Overlapping Fields
    println!("\n=== Test 5: Overlapping Fields (OverlappingFieldsCanBeMerged) ===");
    println!("Testing the validation rule that caused issues in graphql-js...\n");
    println!(
        "{:>4} | {:>12} | {:>12} | {:>8}",
        "Frags", "Validation", "Parse", "Ratio"
    );
    println!("{:-<4}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");

    let mut prev_validation_time = None;
    for count in [10, 20, 30, 40, 50, 75, 100, 150] {
        let result = test_overlapping_fields(count);
        let ratio = if let Some(prev) = prev_validation_time {
            result.validation_time_us as f64 / prev as f64
        } else {
            1.0
        };

        println!(
            "{:>4} | {:>10.3} ms | {:>10.3} ms | {:>7.2}x",
            count,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0,
            ratio
        );

        prev_validation_time = Some(result.validation_time_us);
        results.push(result);
    }

    // Test Category 6: Large Selection Sets (baseline)
    println!("\n=== Test 6: Large Selection Sets (Baseline) ===");
    println!("Testing validation with many fields (non-fragment baseline)...\n");
    println!(
        "{:>6} | {:>12} | {:>12} | {:>8}",
        "Fields", "Validation", "Parse", "Ratio"
    );
    println!("{:-<6}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");

    let mut prev_validation_time = None;
    for count in [100, 500, 1000, 2000, 5000] {
        let result = test_large_selection_set(count);
        let ratio = if let Some(prev) = prev_validation_time {
            result.validation_time_us as f64 / prev as f64
        } else {
            1.0
        };

        println!(
            "{:>6} | {:>10.3} ms | {:>10.3} ms | {:>7.2}x",
            count,
            result.validation_time_us as f64 / 1000.0,
            result.parse_time_us as f64 / 1000.0,
            ratio
        );

        prev_validation_time = Some(result.validation_time_us);
        results.push(result);
    }

    // Output CSV data
    println!("\n=== CSV Output ===");
    println!(
        "test_name,fragment_count,nesting_depth,reuse_factor,validation_time_us,parse_time_us"
    );
    for result in &results {
        println!("{}", result.to_csv_row());
    }

    println!("\n=== Summary ===");
    println!("Total tests run: {}", results.len());
    println!("\nBenchmark complete! Results can be analyzed for complexity characteristics.");
    println!("Expected: Linear or sub-quadratic scaling across all test categories.");
    println!("Failure: Exponential growth (ratios consistently > 2.0)");
}

/// Test 1: Simple fragments with progressive count
fn test_simple_fragments(count: usize) -> BenchmarkResult {
    let query = generate_simple_fragments(count);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "simple_fragments".to_string(),
        fragment_count: count,
        nesting_depth: 0,
        reuse_factor: 1,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Test 2: Nested fragments (fragments spreading other fragments)
fn test_nested_fragments(depth: usize) -> BenchmarkResult {
    let query = generate_nested_fragments(depth);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "nested_fragments".to_string(),
        fragment_count: depth,
        nesting_depth: depth,
        reuse_factor: 1,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Test 3: Fragment reuse (same fragment spread multiple times)
fn test_fragment_reuse(reuse_count: usize) -> BenchmarkResult {
    let query = generate_fragment_reuse(reuse_count);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "fragment_reuse".to_string(),
        fragment_count: 1,
        nesting_depth: 0,
        reuse_factor: reuse_count,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Test 4: Pathological case (nested + reused)
fn test_pathological_case(depth: usize, reuse: usize) -> BenchmarkResult {
    let query = generate_pathological_case(depth, reuse);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "pathological".to_string(),
        fragment_count: depth * reuse,
        nesting_depth: depth,
        reuse_factor: reuse,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Test 5: Overlapping fields that must be merged
fn test_overlapping_fields(count: usize) -> BenchmarkResult {
    let query = generate_overlapping_fields(count);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "overlapping_fields".to_string(),
        fragment_count: count,
        nesting_depth: 1,
        reuse_factor: 1,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Test 6: Large selection set (baseline)
fn test_large_selection_set(field_count: usize) -> BenchmarkResult {
    let query = generate_large_selection_set(field_count);
    let (parse_time, validation_time) = measure_validation(&query);

    BenchmarkResult {
        test_name: "large_selection".to_string(),
        fragment_count: 0,
        nesting_depth: 0,
        reuse_factor: 1,
        validation_time_us: validation_time.as_micros() as u64,
        parse_time_us: parse_time.as_micros() as u64,
    }
}

/// Measure validation time for a query
fn measure_validation(query: &str) -> (Duration, Duration) {
    use apollo_compiler::parser::Parser;

    // Parse
    let parse_start = Instant::now();
    let parser = &mut Parser::new();
    let ast = parser.parse_ast(query, "query.graphql").unwrap();
    let parse_time = parse_start.elapsed();

    // Validate
    let schema_ast = Parser::new()
        .parse_ast(TEST_SCHEMA, "schema.graphql")
        .unwrap();
    let schema = schema_ast.to_schema_validate().unwrap();

    let validation_start = Instant::now();
    let _result = ast.to_executable_validate(&schema);
    let validation_time = validation_start.elapsed();

    (parse_time, validation_time)
}

// Query Generators

fn generate_simple_fragments(count: usize) -> String {
    let mut query = String::from("query TestQuery {\n");

    // Spread all fragments
    for i in 1..=count {
        writeln!(query, "  ...F{}", i).unwrap();
    }

    query.push_str("}\n\n");

    // Define all fragments
    for i in 1..=count {
        let field_idx = (i % 50) + 1;
        writeln!(
            query,
            "fragment F{} on Query {{\n  field{}\n}}",
            i, field_idx
        )
        .unwrap();
    }

    query
}

fn generate_nested_fragments(depth: usize) -> String {
    let mut query = String::from("query TestQuery {\n  ...F1\n}\n\n");

    for i in 1..=depth {
        let field_idx = (i % 50) + 1;
        query.push_str(&format!("fragment F{} on Query {{\n", i));
        query.push_str(&format!("  field{}\n", field_idx));

        if i < depth {
            query.push_str(&format!("  ...F{}\n", i + 1));
        }

        query.push_str("}\n\n");
    }

    query
}

fn generate_fragment_reuse(reuse_count: usize) -> String {
    let mut query = String::from("query TestQuery {\n");

    // Spread the same fragment many times across different fields
    // For counts > 50, we wrap around and reuse fields (which is fine for testing)
    for i in 1..=reuse_count {
        let field_idx = ((i - 1) % 50) + 1;
        writeln!(
            query,
            "  field{} {{\n    ...CommonFragment\n  }}",
            field_idx
        )
        .unwrap();
    }

    query.push_str("}\n\n");
    query.push_str("fragment CommonFragment on ObjectType {\n");
    query.push_str("  subField1\n");
    query.push_str("  subField2\n");
    query.push_str("  subField3\n");
    query.push_str("}\n");

    query
}

fn generate_pathological_case(depth: usize, reuse: usize) -> String {
    let mut query = String::from("query TestQuery {\n");

    // Top level: spread level 1 fragments multiple times
    for r in 0..reuse {
        writeln!(query, "  ...L1_{}", r).unwrap();
    }

    query.push_str("}\n\n");

    // Generate nested and reused fragments
    for level in 1..=depth {
        for r in 0..reuse {
            let field_idx = ((level * reuse + r) % 50) + 1;
            writeln!(query, "fragment L{}_{} on Query {{", level, r).unwrap();
            writeln!(query, "  field{}", field_idx).unwrap();

            // Spread next level fragments
            if level < depth {
                for next_r in 0..reuse {
                    writeln!(query, "  ...L{}_{}", level + 1, next_r).unwrap();
                }
            }

            query.push_str("}\n\n");
        }
    }

    query
}

fn generate_overlapping_fields(count: usize) -> String {
    let mut query = String::from("query TestQuery {\n");

    // Spread all fragments
    for i in 1..=count {
        writeln!(query, "  ...F{}", i).unwrap();
    }

    query.push_str("}\n\n");

    // Each fragment queries the same field (overlapping)
    for i in 1..=count {
        writeln!(query, "fragment F{} on Query {{", i).unwrap();
        writeln!(query, "  field1 {{").unwrap();
        writeln!(query, "    subField1").unwrap();
        writeln!(query, "    subField2").unwrap();
        writeln!(query, "  }}").unwrap();

        // Also spread a common fragment
        if i > 1 {
            writeln!(query, "  ...CommonBase").unwrap();
        }

        writeln!(query, "}}").unwrap();
        writeln!(query).unwrap();
    }

    // Common base fragment
    query.push_str("fragment CommonBase on Query {\n");
    query.push_str("  field2 { subField1 }\n");
    query.push_str("}\n");

    query
}

fn generate_large_selection_set(field_count: usize) -> String {
    let mut query = String::from("query TestQuery {\n");

    for i in 1..=field_count.min(50) {
        writeln!(query, "  field{}", i).unwrap();
    }

    query.push_str("}\n");
    query
}
