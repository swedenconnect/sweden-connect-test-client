/*
 * Copyright 2025-2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.testclient.utils;

import jakarta.annotation.Nonnull;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * Sorts entities, such as IdP:s and OP:s, by matching their identifiers against a list of patterns.
 * <p>
 * A pattern matches an identifier if it occurs anywhere in it, ignoring case. The entities are grouped by the first
 * pattern they match, and the groups are listed in the order the patterns are given. Entities that match no pattern
 * come last. An empty pattern matches nothing. Within each group, the entities keep the order they were given in.
 * </p>
 *
 * @author Martin Lindström
 */
public final class IdentifierSorting {

  private IdentifierSorting() {
  }

  /**
   * Sorts the supplied entities according to the patterns.
   *
   * @param entities the entities to sort
   * @param identifier gives the identifier of an entity
   * @param patterns the patterns, in order of priority
   * @param <T> the entity type
   * @return a new list holding the sorted entities
   */
  @Nonnull
  public static <T> List<T> sort(@Nonnull final List<T> entities, @Nonnull final Function<T, String> identifier,
      @Nonnull final List<String> patterns) {

    final List<String> lowerCasePatterns = patterns.stream()
        .map(p -> p.toLowerCase(Locale.ROOT))
        .toList();
    final List<List<T>> groups = new ArrayList<>();
    for (int i = 0; i <= lowerCasePatterns.size(); i++) {
      groups.add(new ArrayList<>());
    }
    for (final T entity : entities) {
      final String id = identifier.apply(entity).toLowerCase(Locale.ROOT);
      int group = lowerCasePatterns.size();
      for (int i = 0; i < lowerCasePatterns.size(); i++) {
        if (!lowerCasePatterns.get(i).isEmpty() && id.contains(lowerCasePatterns.get(i))) {
          group = i;
          break;
        }
      }
      groups.get(group).add(entity);
    }
    return groups.stream().flatMap(List::stream).toList();
  }

}
