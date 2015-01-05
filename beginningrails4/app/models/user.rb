require 'digest'
class User < ActiveRecord::Base
  validates_uniqueness_of :email
  validates_length_of :email, :within => 5..50
  validates_format_of :email, :with => /^[^@][\w.-]+@[\w.-]+[.][a-z]{2,4}$/i
  #validates_format_of :email, :with => /^([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})$/i
  validates_confirmation_of :password
  validates_length_of :password, :within => 4..20
  validates_presence_of :password, :if => :password_required?
  has_one :profile
  has_many :articles, -> {order('published_at DESC, title ASC')},
           :dependent => :nullify
  has_many :replies, :through => :articles, :source => :comments
  before_save :encrypt_new_password
  def self.authenticate(email, password)
    user = find_by_email(email)
    return user if user && user.authenticated?(password)
  end
  def authenticated?(password)
    self.hashed_password == encrypt(password)
  end

  protected
  def encrypt_new_password
    return if password.blank?
    self.hashed_password = encrypt(password)
  end
  def password_required?
    hashed_password.blank? || password_required?
  end
  def encrypt(string)
    Digest :: SHA1.hexdigest(string)
  end
end


#require 'digest' : Bạn bắt đầu bằng cách yêu cầu các thư viện Digest bạn sử dụng để mã hóa mật khẩu. Điều này tải
# các thư viện cần thiết và làm cho nó có sẵn để làm việc trong lớp của bạn.

#attr_accessor: password: Điều này xác định một thuộc tính accessor, mật khẩu, ở phía trên của cơ thể lớp.
# Nó nói với Ruby để tạo ra phương pháp đọc và người viết cho mật khẩu. Bởi vì các cột mật khẩu không tồn tại
# trong bảng của bạn nữa, một phương pháp mật khẩu không được tạo ra tự động bởi Active Record. Tuy nhiên, bạn cần một
# cách để thiết lập mật khẩu trước khi nó được mã hóa, do đó, bạn làm cho thuộc tính riêng của bạn để sử dụng.
# Điều này hoạt động giống như bất kỳ thuộc tính mô hình, ngoại trừ việc nó không được tiếp tục tồn tại để các cơ sở
# dữ liệu khi mô hình được lưu.

#before_save: encrypt_new_password: callback before_save này cho Active Record để chạy các phương pháp
# encrypt_new_password trước khi nó tiết kiệm một kỷ lục. Điều đó có nghĩa là nó được áp dụng cho tất cả các
# hoạt động kích hoạt một lưu, bao gồm tạo ra và cập nhật.

#encrypt_new_password: Phương pháp này nên thực hiện mã hóa chỉ nếu thuộc tính mật khẩu có chứa một giá trị,
# bởi vì bạn không muốn nó xảy ra, trừ khi một người dùng đang thay đổi mật khẩu của mình.
# Nếu thuộc tính password là trống, bạn trở về từ phương pháp,
# và các giá trị hash_password không bao giờ được thiết lập.
# Nếu các giá trị mật khẩu không được để trống, bạn có một số việc phải làm.
#Bạn thiết lập các thuộc tính hashed_password với phiên bản mã hóa của mật khẩu bằng cách rửa nó thông qua
# các phương pháp mã hóa.

# encrypt: Phương pháp này khá đơn giản. Nó sử dụng thư viện Digest của Ruby, mà bạn đưa vào dòng đầu tiên,
# để tạo ra một SHA1 tiêu hóa của bất cứ điều gì bạn vượt qua nó.
# Bởi vì phương pháp trong Ruby luôn luôn trở lại điều cuối cùng đánh giá, mã hóa trả về chuỗi được mã hóa.

#password_required ?: Khi bạn thực hiện kiểm chứng thực, bạn muốn chắc chắn rằng bạn đang xác nhận sự hiện diện,
# chiều dài, và xác nhận mật khẩu chỉ khi xác nhận được yêu cầu. Và nó chỉ yêu cầu nếu điều này là một kỷ lục mới
# (các thuộc tính hashed_password là trống) hoặc nếu các accessor mật khẩu mà bạn tạo ra đã được sử dụng để thiết
# lập một mật khẩu mới (password.present?). Để thực hiện điều này dễ dàng, bạn tạo ra các password_required?
# phương pháp ngữ, mà trả về true nếu một mật khẩu được yêu cầu hoặc false nếu nó không phải.
# Sau đó bạn áp dụng phương pháp này như một: nếu tình trạng trên tất cả các xác nhận mật khẩu của bạn.

#self.authenticate: Bạn có thể nói đây là một phương pháp học bởi vì nó bắt đầu bằng tự
# (nó được định nghĩa trên lớp đó). Điều đó có nghĩa là bạn không truy cập nó thông qua một ví dụ;
# bạn truy cập trực tiếp ra khỏi lớp học, cũng giống như bạn sẽ thấy, mới, hoặc tạo (User.authenticate,
# no @user = User.new; @ user.authenticate).
# Các phương pháp xác thực chấp nhận một địa chỉ e-mail và mật khẩu không được mã hóa.
# Nó sử dụng một công cụ tìm động (find_by_email) để lấy các người dùng với một địa chỉ e-mail hợp.
# Nếu người sử dụng được tìm thấy, các biến sử dụng có chứa một đối tượng người dùng; nếu không, đó là con số không.
# Biết được điều này, bạn có thể trả về giá trị của người sử dụng nếu, và chỉ nếu, nó không phải là con số không và
# chứng thực? phương thức trả về đúng với mật khẩu được (dùng && người dùng. chứng thực? (password)).

#authenticated?: Đây là một phương pháp đơn giản để kiểm tra vị để đảm bảo hashed_password lưu trữ phù hợp với
# mật khẩu được sau khi nó đã được mã hóa (thông qua encrypt). Nếu nó phù hợp, đúng được trả về.






























