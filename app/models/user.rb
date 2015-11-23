class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :omniauthable, :omniauth_providers => [:facebook, :google_oauth2, :twitter]

  class << self
		def from_omniauth(auth)
			binding.pry
			identity = User.where(provider: auth.provider, uid: auth.uid).first_or_create do |identity|
			  identity.provider     = auth.provider
			  identity.uid          = auth.uid
			  identity.email        = auth.info.email if auth.info.email
			  identity.password     = Devise.friendly_token.first(8)
			end
			identity.save!
			identity
		end
	end

end
