class Comment < ActiveRecord::Base
  belongs_to :article
  validates_presence_of :name, :email, :body
  validate :article_should_be_published
  after_create :email_article_author
  def article_should_be_published
    errors.add(:article_id, "is not published yet") if article && !article.published?
  end
  def after_create
    puts "we will notify the author in Chapter 9"
  end
end
