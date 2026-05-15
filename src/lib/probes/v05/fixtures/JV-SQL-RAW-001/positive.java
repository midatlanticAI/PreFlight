// XL-002 / JV-SQL-RAW-001 positive fixture.
// JPQL built by concatenating the user value into the query string.
public class UserRepo {
    User find(EntityManager em, String name) {
        return (User) em.createQuery("FROM User WHERE name = '" + name + "'").getSingleResult();
    }
}
