import triton_python_backend_utils as pb_utils


class TritonPythonModel:
    def execute(self, requests):
        responses = []
        for request in requests:
            in_tensor = pb_utils.get_input_tensor_by_name(request, "INPUT0")
            out_tensor = pb_utils.Tensor("OUTPUT0", in_tensor.as_numpy())
            responses.append(pb_utils.InferenceResponse(output_tensors=[out_tensor]))
        return responses
