// XL-002 / JV-SQL-RAW-001 negative fixture.
// Bound named parameter; no concatenation.
public class UserRepo {
    User find(EntityManager em, String name) {
        return (User) em.createQuery("FROM User WHERE name = :n").setParameter("n", name).getSingleResult();
    }
}
