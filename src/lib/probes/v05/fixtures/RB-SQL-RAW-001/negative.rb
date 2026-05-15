# XL-002 / RB-SQL-RAW-001 negative fixture.
# Hash form: ActiveRecord binds the value, no interpolation.
def find_user(name)
  User.where(name: name)
end
