# XL-002 / RB-SQL-RAW-001 positive fixture.
# String interpolation into an ActiveRecord where clause.
def find_user(name)
  User.where("name = '#{name}'")
end
