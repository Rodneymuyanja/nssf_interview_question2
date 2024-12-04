using objects;

namespace question2.Interfaces
{
    public interface IPaymentLogic
    {
        PaymentRequest GetPayment(string id);
        void InitiatePayment(PaymentRequest paymentRequest);

        List<PaymentRequest> GetAllPayments();
    }
}