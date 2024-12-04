
namespace objects
{
    public enum Status
    {
        PENDING,COMPLETED,FAILED
    }

    public enum PaymentMethod
    {
        MOMO, CARD, BANK_TRANSFER
    }
    public class PaymentRequest
    {
        public int Id { get; set; } 
        public decimal  Amount { get; set; }
        public required string Currency { get; set; }    
        public Status Status { get; set; }
        public PaymentMethod PaymentMethod { get; set; }
        public DateTime Created_at { get; set; }    
        public DateTime Updated_at { get; set; }
    }
}