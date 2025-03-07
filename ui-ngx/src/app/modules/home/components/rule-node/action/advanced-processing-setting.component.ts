///
/// Copyright © 2016-2025 The Thingsboard Authors
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
///

import {
  ControlValueAccessor,
  FormBuilder,
  NG_VALIDATORS,
  NG_VALUE_ACCESSOR,
  ValidationErrors,
  Validator
} from '@angular/forms';
import { Component, forwardRef } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AdvancedProcessingStrategy } from '@home/components/rule-node/action/timeseries-config.models';

@Component({
  selector: 'tb-advanced-processing-settings',
  templateUrl: './advanced-processing-setting.component.html',
  providers: [{
    provide: NG_VALUE_ACCESSOR,
    useExisting: forwardRef(() => AdvancedProcessingSettingComponent),
    multi: true
  },{
    provide: NG_VALIDATORS,
    useExisting: forwardRef(() => AdvancedProcessingSettingComponent),
    multi: true
  }]
})
export class AdvancedProcessingSettingComponent implements ControlValueAccessor, Validator {

  processingForm = this.fb.group({
    timeseries: [null],
    latest: [null],
    webSockets: [null],
    calculatedFields: [null]
  });

  private propagateChange: (value: any) => void = () => {};

  constructor(private fb: FormBuilder) {
    this.processingForm.valueChanges.pipe(
      takeUntilDestroyed()
    ).subscribe(value => this.propagateChange(value));
  }

  registerOnChange(fn: any) {
    this.propagateChange = fn;
  }

  registerOnTouched(_fn: any) {
  }

  setDisabledState(isDisabled: boolean) {
    if (isDisabled) {
      this.processingForm.disable({emitEvent: false});
    } else {
      this.processingForm.enable({emitEvent: false});
    }
  }

  validate(): ValidationErrors | null {
    return this.processingForm.valid ? null : {
      processingForm: false
    };
  }

  writeValue(value: AdvancedProcessingStrategy) {
    this.processingForm.patchValue(value, {emitEvent: false});
  }
}
