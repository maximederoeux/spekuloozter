class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable


  def generate_username
  	"#{self.email[/^[^@]*/]}_#{user.id.to_s[0..5]}"
  end
end
