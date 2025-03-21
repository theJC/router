use apollo_compiler::Schema;
use apollo_compiler::executable;
use apollo_compiler::executable::FieldSet;
use apollo_compiler::schema::ExtendedType;
use apollo_compiler::schema::NamedType;
use apollo_compiler::validation::Valid;

use crate::error::FederationError;
use crate::error::MultipleFederationErrors;
use crate::error::SingleFederationError;
use crate::operation::Selection;
use crate::operation::SelectionSet;
use crate::schema::ValidFederationSchema;
use crate::schema::position::CompositeTypeDefinitionPosition;
use crate::schema::position::FieldDefinitionPosition;
use crate::schema::position::InterfaceTypeDefinitionPosition;
use crate::schema::position::ObjectTypeDefinitionPosition;
use crate::schema::position::UnionTypeDefinitionPosition;

// Federation spec does not allow the alias syntax in field set strings.
// However, since `parse_field_set` uses the standard GraphQL parser, which allows aliases,
// we need this secondary check to ensure that aliases are not used.
fn check_absence_of_aliases(selection_set: &SelectionSet) -> Result<(), FederationError> {
    fn visit_selection_set(
        errors: &mut MultipleFederationErrors,
        selection_set: &SelectionSet,
    ) -> Result<(), FederationError> {
        for selection in selection_set.iter() {
            match selection {
                Selection::InlineFragment(frag) => check_absence_of_aliases(&frag.selection_set)?,
                Selection::Field(field) => {
                    if let Some(alias) = &field.field.alias {
                        errors.push(SingleFederationError::UnsupportedFeature {
                            // PORT_NOTE: The JS version also quotes the directive name in the error message.
                            //            For example, "aliases are not currently supported in @requires".
                            message: format!(r#"Cannot use alias "{alias}" in "{}": aliases are not currently supported in the used directive"#, field.field),
                            kind: crate::error::UnsupportedFeatureKind::Alias
                        }.into());
                    }
                    if let Some(selection_set) = &field.selection_set {
                        visit_selection_set(errors, selection_set)?;
                    }
                }
            }
        }
        Ok(())
    }

    let mut errors = MultipleFederationErrors { errors: vec![] };
    visit_selection_set(&mut errors, selection_set)?;
    errors.into_result()
}

// TODO: In the JS codebase, this has some error-rewriting to help give the user better hints around
// non-existent fields.
pub(crate) fn parse_field_set(
    schema: &ValidFederationSchema,
    parent_type_name: NamedType,
    field_set: &str,
) -> Result<SelectionSet, FederationError> {
    // Note this parsing takes care of adding curly braces ("{" and "}") if they aren't in the
    // string.
    let field_set = FieldSet::parse_and_validate(
        schema.schema(),
        parent_type_name,
        field_set,
        "field_set.graphql",
    )?;

    // A field set should not contain any named fragments.
    let fragments = Default::default();
    let selection_set =
        SelectionSet::from_selection_set(&field_set.selection_set, &fragments, schema, &||
            // never cancel
            Ok(()))?;

    // Validate that the field set has no aliases.
    check_absence_of_aliases(&selection_set)?;

    Ok(selection_set)
}

/// This exists because there's a single callsite in extract_subgraphs_from_supergraph() that needs
/// to parse field sets before the schema has finished building. Outside that case, you should
/// always use `parse_field_set()` instead.
// TODO: As noted in the single callsite, ideally we could move the parsing to after extraction, but
// it takes time to determine whether that impacts correctness, so we're leaving it for later.
pub(crate) fn parse_field_set_without_normalization(
    schema: &Valid<Schema>,
    parent_type_name: NamedType,
    field_set: &str,
) -> Result<executable::SelectionSet, FederationError> {
    // Note this parsing takes care of adding curly braces ("{" and "}") if they aren't in the
    // string.
    let field_set =
        FieldSet::parse_and_validate(schema, parent_type_name, field_set, "field_set.graphql")?;
    Ok(field_set.into_inner().selection_set)
}

// PORT_NOTE: The JS codebase called this `collectTargetFields()`, but this naming didn't make it
// apparent that this was collecting from a field set, so we've renamed it accordingly. Note that
// the JS function also optionally collected interface field implementations, but we've split that
// off into a separate function.
pub(crate) fn collect_target_fields_from_field_set(
    schema: &Valid<Schema>,
    parent_type_name: NamedType,
    field_set: &str,
    validate: bool,
) -> Result<Vec<FieldDefinitionPosition>, FederationError> {
    // Note this parsing takes care of adding curly braces ("{" and "}") if they aren't in the string.
    let field_set = if validate {
        FieldSet::parse_and_validate(schema, parent_type_name, field_set, "field_set.graphql")?
    } else {
        // This case exists for when a directive's field set uses an interface I with implementer O, and conditions
        // I on O, but the actual phrase "type O implements I" only exists in another subgraph. Ideally, this wouldn't
        // be allowed, but it would be a breaking change to remove it, thus it's supported for legacy reasons.
        Valid::assume_valid(FieldSet::parse(
            schema,
            parent_type_name,
            field_set,
            "field_set.graphql",
        )?)
    };
    let mut stack = vec![&field_set.selection_set];
    let mut fields = vec![];
    while let Some(selection_set) = stack.pop() {
        let Some(parent_type) = schema.types.get(&selection_set.ty) else {
            return Err(FederationError::internal(
                "Unexpectedly missing selection set type from schema.",
            ));
        };
        let parent_type_position: CompositeTypeDefinitionPosition = match parent_type {
            ExtendedType::Object(_) => ObjectTypeDefinitionPosition {
                type_name: selection_set.ty.clone(),
            }
            .into(),
            ExtendedType::Interface(_) => InterfaceTypeDefinitionPosition {
                type_name: selection_set.ty.clone(),
            }
            .into(),
            ExtendedType::Union(_) => UnionTypeDefinitionPosition {
                type_name: selection_set.ty.clone(),
            }
            .into(),
            _ => {
                return Err(FederationError::internal(
                    "Unexpectedly encountered non-composite type for selection set.",
                ));
            }
        };
        // The stack iterates through what we push in reverse order, so we iterate through
        // selections in reverse order to fix it.
        for selection in selection_set.selections.iter().rev() {
            match selection {
                executable::Selection::Field(field) => {
                    fields.push(parent_type_position.field(field.name.clone())?);
                    if !field.selection_set.selections.is_empty() {
                        stack.push(&field.selection_set);
                    }
                }
                executable::Selection::FragmentSpread(_) => {
                    return Err(FederationError::internal(
                        "Unexpectedly encountered fragment spread in FieldSet.",
                    ));
                }
                executable::Selection::InlineFragment(inline_fragment) => {
                    stack.push(&inline_fragment.selection_set);
                }
            }
        }
    }
    Ok(fields)
}

pub(crate) fn parse_field_value_without_validation(
    schema: &ValidFederationSchema,
    parent_type_name: NamedType,
    field_value: &str,
) -> Result<FieldSet, FederationError> {
    // Note this parsing takes care of adding curly braces ("{" and "}") if they aren't in the
    // string.
    Ok(FieldSet::parse(
        schema.schema(),
        parent_type_name,
        field_value,
        "field_set.graphql",
    )?)
}

// Similar to parse_field_set(), we explicitly forbid aliases for field values. In this case though,
// it's because field value evaluation semantics means aliases would be stripped out and have no
// effect.
pub(crate) fn validate_field_value(
    schema: &ValidFederationSchema,
    field_value: FieldSet,
) -> Result<SelectionSet, FederationError> {
    field_value.validate(schema.schema())?;

    // A field value should not contain any named fragments.
    let fragments = Default::default();
    let selection_set =
        SelectionSet::from_selection_set(&field_value.selection_set, &fragments, schema, &|| {
            // never cancel
            Ok(())
        })?;

    // Validate that the field value has no aliases.
    check_absence_of_aliases(&selection_set)?;

    Ok(selection_set)
}

#[cfg(test)]
mod tests {
    use apollo_compiler::Name;

    use crate::Supergraph;
    use crate::error::FederationError;
    use crate::query_graph::build_federated_query_graph;
    use crate::subgraph::Subgraph;

    #[test]
    fn test_aliases_in_field_set() -> Result<(), FederationError> {
        let sdl = r#"
        type Query {
            a: Int! @requires(fields: "r1: r")
            r: Int! @external
          }
        "#;

        let subgraph = Subgraph::parse_and_expand("S1", "http://S1", sdl).unwrap();
        let supergraph = Supergraph::compose([&subgraph].to_vec()).unwrap();
        let err = super::parse_field_set(&supergraph.schema, Name::new("Query").unwrap(), "r1: r")
            .map(|_| "Unexpected success") // ignore the Ok value
            .expect_err("Expected alias error");
        assert_eq!(
            err.to_string(),
            r#"Cannot use alias "r1" in "r1: r": aliases are not currently supported in the used directive"#
        );
        Ok(())
    }

    #[test]
    fn test_aliases_in_field_set_via_build_federated_query_graph() -> Result<(), FederationError> {
        // NB: This tests multiple alias errors in the same field set.
        let sdl = r#"
        type Query {
            a: Int! @requires(fields: "r1: r s q1: q")
            r: Int! @external
            s: String! @external
            q: String! @external
          }
        "#;

        let subgraph = Subgraph::parse_and_expand("S1", "http://S1", sdl).unwrap();
        let supergraph = Supergraph::compose([&subgraph].to_vec()).unwrap();
        let api_schema = supergraph.to_api_schema(Default::default())?;
        // Testing via `build_federated_query_graph` function, which validates the @requires directive.
        let err = build_federated_query_graph(supergraph.schema, api_schema, None, None)
            .map(|_| "Unexpected success") // ignore the Ok value
            .expect_err("Expected alias error");
        assert_eq!(
            err.to_string(),
            r#"The following errors occurred:
  - Cannot use alias "r1" in "r1: r": aliases are not currently supported in the used directive
  - Cannot use alias "q1" in "q1: q": aliases are not currently supported in the used directive"#
        );
        Ok(())
    }
}
